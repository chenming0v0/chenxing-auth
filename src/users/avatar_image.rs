//! 头像图片规范化。
//!
//! 上传字节是不可信输入，本模块是它唯一的准入关口：判定格式、限制解码规模、
//! 校验尺寸下限，然后**重新编码**成固定规格的 JPEG。落库的永远是本模块的输出，
//! 不是上传的原始字节——这既把存储占用钉死在一个上界，也让任何藏在原文件里的
//! 元数据（EXIF、附加块、多帧数据）在重编码过程中被丢弃。

use image::{DynamicImage, ImageEncoder, ImageFormat, ImageReader, Limits, RgbImage};
use std::io::Cursor;

/// 上传体上限（5 MiB），与路由层 `DefaultBodyLimit` 和前端预检共用同一个数字。
pub const MAX_UPLOAD_BYTES: usize = 5 * 1024 * 1024;

/// 源图最短边下限。低于此值放大到落库规格只会得到一张糊图，直接拒绝更诚实。
pub const MIN_SOURCE_EDGE: u32 = 250;

/// 落库边长。头像最大展示尺寸是 96 CSS px，256 给到 2.6x 像素密度余量。
pub const STORED_EDGE: u32 = 256;

/// 落库 MIME。
pub const STORED_MIME: &str = "image/jpeg";

/// JPEG 质量。82 是 256x256 人像上肉眼无损与体积（约 20 KiB）的常用平衡点。
const JPEG_QUALITY: u8 = 82;

/// 解码期边长上限。配合 `MAX_DECODE_ALLOC` 拦住解压炸弹：几十 KiB 的文件头
/// 可以声明上亿像素，若不设限，分配会在解码阶段直接打爆内存。
const MAX_DECODE_EDGE: u32 = 8192;

/// 解码期分配上限（128 MiB）。8192x8192 RGBA 恰好 256 MiB，故取其半作为硬顶。
const MAX_DECODE_ALLOC: u64 = 128 * 1024 * 1024;

/// alpha 拍平到的背景色，与前端 `--chenxing-background` 一致。
/// JPEG 无 alpha 通道，透明像素必须先合成到确定底色，否则会被填成黑或白。
const FLATTEN_BACKGROUND: [u8; 3] = [0x04, 0x06, 0x0d];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AvatarImageError {
    #[error("avatar upload is empty")]
    Empty,
    #[error("avatar upload exceeds the size limit")]
    TooLarge,
    #[error("avatar format is not supported")]
    UnsupportedFormat,
    #[error("avatar image could not be decoded")]
    Undecodable,
    #[error("avatar image is smaller than the minimum edge")]
    TooSmall,
    #[error("avatar image could not be encoded")]
    EncodeFailed,
}

/// 规范化结果，即将落库的字节。
#[derive(Debug, PartialEq, Eq)]
pub struct NormalizedAvatar {
    pub bytes: Vec<u8>,
    pub mime: &'static str,
}

/// 把不可信上传字节规范化成固定规格头像。
///
/// 调用方必须在阻塞线程池上执行本函数：解码与缩放是 CPU 密集操作，5 MiB 的
/// JPEG 可达数十毫秒，留在异步执行器上会阻塞同一 worker 的其他请求。
pub fn normalize(input: &[u8]) -> Result<NormalizedAvatar, AvatarImageError> {
    if input.is_empty() {
        return Err(AvatarImageError::Empty);
    }
    if input.len() > MAX_UPLOAD_BYTES {
        return Err(AvatarImageError::TooLarge);
    }

    let decoded = decode(input)?;
    if decoded.width() < MIN_SOURCE_EDGE || decoded.height() < MIN_SOURCE_EDGE {
        return Err(AvatarImageError::TooSmall);
    }

    // resize_to_fill 居中裁剪出正方形再缩放。前端已裁好方图时这一步退化为等比
    // 缩放；直接 PUT 非方图的客户端也拿不到变形结果。
    let square = decoded.resize_to_fill(STORED_EDGE, STORED_EDGE, image::imageops::Lanczos3);
    encode_jpeg(&flatten_alpha(square))
}

/// 解码并施加规模上限。
///
/// 格式一律由字节魔数判定，不读 `Content-Type`：客户端声明的类型不可信，而把
/// 声明类型喂给解码器等于让调用方选择走哪个解析器。
fn decode(input: &[u8]) -> Result<DynamicImage, AvatarImageError> {
    let format = match image::guess_format(input) {
        Ok(format @ (ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP)) => format,
        _ => return Err(AvatarImageError::UnsupportedFormat),
    };

    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DECODE_EDGE);
    limits.max_image_height = Some(MAX_DECODE_EDGE);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);

    let mut reader = ImageReader::new(Cursor::new(input));
    reader.set_format(format);
    reader.limits(limits);
    reader.decode().map_err(|_| AvatarImageError::Undecodable)
}

/// 把 alpha 合成到固定背景色。
///
/// 无 alpha 时走 `to_rgb8` 的快路径；有 alpha 时必须手工混合而不能直接丢弃
/// 通道，否则半透明像素会带着未预乘的原色突然变亮。
fn flatten_alpha(image: DynamicImage) -> RgbImage {
    if !image.color().has_alpha() {
        return image.to_rgb8();
    }
    let source = image.to_rgba8();
    let mut output = RgbImage::new(source.width(), source.height());
    for (target, pixel) in output.pixels_mut().zip(source.pixels()) {
        let alpha = u32::from(pixel[3]);
        let blend = |channel: usize, background: u8| -> u8 {
            let foreground = u32::from(pixel[channel]) * alpha;
            let backdrop = u32::from(background) * (255 - alpha);
            // +127 做四舍五入，避免整除的系统性偏暗。
            ((foreground + backdrop + 127) / 255) as u8
        };
        *target = image::Rgb([
            blend(0, FLATTEN_BACKGROUND[0]),
            blend(1, FLATTEN_BACKGROUND[1]),
            blend(2, FLATTEN_BACKGROUND[2]),
        ]);
    }
    output
}

fn encode_jpeg(image: &RgbImage) -> Result<NormalizedAvatar, AvatarImageError> {
    let mut bytes = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, JPEG_QUALITY)
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::Rgb8,
        )
        .map_err(|_| AvatarImageError::EncodeFailed)?;
    Ok(NormalizedAvatar {
        bytes,
        mime: STORED_MIME,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageFormat, Rgba, RgbaImage};

    /// 生成一张带 alpha 的测试 PNG。
    fn png_fixture(width: u32, height: u32) -> Vec<u8> {
        let mut image = RgbaImage::new(width, height);
        for (x, y, pixel) in image.enumerate_pixels_mut() {
            let alpha = if x < width / 2 { 255 } else { 0 };
            *pixel = Rgba([(x % 256) as u8, (y % 256) as u8, 128, alpha]);
        }
        let mut bytes = Vec::new();
        DynamicImage::ImageRgba8(image)
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .expect("fixture encodes");
        bytes
    }

    #[test]
    fn normalize_re_encodes_to_a_fixed_jpeg_square() {
        let normalized = normalize(&png_fixture(600, 400)).expect("normalizes");

        assert_eq!(normalized.mime, STORED_MIME);
        assert_eq!(
            image::guess_format(&normalized.bytes).expect("format"),
            ImageFormat::Jpeg,
            "stored bytes must be re-encoded, never the uploaded PNG"
        );
        let stored = image::load_from_memory(&normalized.bytes).expect("stored decodes");
        assert_eq!(
            (stored.width(), stored.height()),
            (STORED_EDGE, STORED_EDGE)
        );
    }

    #[test]
    fn normalize_compresses_a_large_upload_far_below_the_upload_limit() {
        // 存储可控性是本功能的硬需求：无论上传多大，落库体积都被重编码钉住。
        let upload = png_fixture(2000, 2000);
        let normalized = normalize(&upload).expect("normalizes");

        assert!(
            normalized.bytes.len() < 64 * 1024,
            "stored avatar must stay tiny, got {} bytes",
            normalized.bytes.len()
        );
        assert!(normalized.bytes.len() < upload.len());
    }

    #[test]
    fn normalize_flattens_alpha_instead_of_dropping_it() {
        let normalized = normalize(&png_fixture(300, 300)).expect("normalizes");
        let stored = image::load_from_memory(&normalized.bytes)
            .expect("stored decodes")
            .to_rgb8();

        // 右半边源像素 alpha=0，必须落在背景色附近而不是纯黑或纯白。
        let pixel = stored.get_pixel(STORED_EDGE - 4, STORED_EDGE / 2);
        for (channel, expected) in pixel.0.iter().zip(FLATTEN_BACKGROUND) {
            assert!(
                channel.abs_diff(expected) <= 12,
                "transparent pixels must blend to the flatten background, got {pixel:?}"
            );
        }
    }

    #[test]
    fn normalize_rejects_sources_below_the_minimum_edge() {
        assert_eq!(
            normalize(&png_fixture(249, 400)),
            Err(AvatarImageError::TooSmall)
        );
    }

    #[test]
    fn normalize_accepts_exactly_the_minimum_edge() {
        assert!(normalize(&png_fixture(MIN_SOURCE_EDGE, MIN_SOURCE_EDGE)).is_ok());
    }

    #[test]
    fn normalize_rejects_empty_and_oversized_uploads() {
        assert_eq!(normalize(&[]), Err(AvatarImageError::Empty));
        assert_eq!(
            normalize(&vec![0u8; MAX_UPLOAD_BYTES + 1]),
            Err(AvatarImageError::TooLarge)
        );
    }

    #[test]
    fn normalize_rejects_formats_outside_the_allowlist() {
        // GIF 魔数：解码器未启用，且不在白名单内，必须在读取前被拒。
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[0u8; 64]);
        assert_eq!(normalize(&gif), Err(AvatarImageError::UnsupportedFormat));
    }

    #[test]
    fn normalize_rejects_bytes_that_only_look_like_an_image() {
        // 合法 PNG 魔数 + 垃圾载荷：格式判定通过但解码必须失败，且不 panic。
        let mut forged = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        forged.extend_from_slice(&[0xab; 256]);
        assert_eq!(normalize(&forged), Err(AvatarImageError::Undecodable));
    }
}
