import { useNavigate } from "react-router-dom";
import { FlaskConical, Plug } from "lucide-react";
import { EmptyState, GhostButton, PageFade, PageHeader, Section } from "../../components/ui";

export default function Connections() {
  const navigate = useNavigate();

  return (
    <PageFade>
      <PageHeader
        title="已授权应用"
        description="你通过辰星通行证登录过的第三方应用会显示在这里。"
      />

      <div className="panel mb-6 rounded-xl">
        <EmptyState
          icon={<Plug size={20} />}
          title="此功能尚未开放"
          description="服务端目前提供授权确认、会话绑定和令牌撤销，但还没有「列出用户已授权应用」的接口。这里不会展示虚构数据，接口就绪后会接上真实记录。"
          action={
            <GhostButton onClick={() => navigate("/console/playground")}>
              <FlaskConical size={14} /> 前往授权测试
            </GhostButton>
          }
        />
      </div>

      <div className="grid gap-5 md:grid-cols-2">
        <Section title="现在可以怎么撤销">
          <p className="text-xs leading-relaxed text-slate-400">
            修改密码会撤销全部历史会话；在通行证资料中也可以单独撤销某个设备的登录会话。第三方应用持有的令牌由服务端的撤销端点处理。
          </p>
        </Section>

        <Section title="平台边界">
          <p className="text-xs leading-relaxed text-slate-400">
            认证中枢只负责身份事实与协议授权。接入方自己的业务账号、角色和数据由各子项目管理，不会出现在这里。
          </p>
        </Section>
      </div>
    </PageFade>
  );
}
