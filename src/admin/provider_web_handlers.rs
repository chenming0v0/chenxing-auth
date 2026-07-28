use axum::{
    extract::State,
    http::HeaderMap,
    response::{Html, IntoResponse, Response},
};

use crate::{
    admin::{authorization::current_admin_permission, domain::AdminPermission},
    sessions::cookies,
    state::AppState,
    web,
};

pub async fn oauth_settings(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        current_admin_permission(&state, &headers, AdminPermission::ManageIdentityProviders).await
    {
        return response;
    }
    let csrf = cookies::cookie_value_by_name(&headers, super::session::ADMIN_CSRF_COOKIE)
        .unwrap_or_default();
    let body = format!(
        r#"<main>
<h1>自定义 OAuth 提供商</h1>
<p>配置符合 OAuth 2.0 授权码流程和 UserInfo JSON 接口的外部身份提供商。</p>
<table><thead><tr><th>名称</th><th>Slug</th><th>回调 URL</th><th>状态</th><th>Secret</th><th>操作</th></tr></thead><tbody id="provider-list"><tr><td colspan="6">正在加载...</td></tr></tbody></table>
<h2 id="provider-form-title">添加提供商</h2>
<form id="provider-form">
<input type="hidden" name="edit_slug" value="">
<label>名称<input name="name" required maxlength="128"></label>
<label>Slug<input name="slug" required pattern="[a-z0-9_-]+" maxlength="64"></label>
<label>授权地址<input name="authorization_endpoint" type="url" required></label>
<label>Token 地址<input name="token_endpoint" type="url" required></label>
<label>UserInfo 地址<input name="userinfo_endpoint" type="url" required></label>
<label>Client ID<input name="client_id" required></label>
<label>Client Secret<input name="client_secret" type="password" autocomplete="new-password"><small>编辑时留空以保留现有 Secret。</small></label>
<label>Scopes<input name="scopes" value="openid profile email" required></label>
<label>Subject Claim<input name="subject_claim" value="sub" required></label>
<label>Email Claim<input name="email_claim" value="email" required></label>
<label>Name Claim<input name="name_claim" value="name"></label>
<label>Email Verified Claim<input name="email_verified_claim" value="email_verified"></label>
<label>Client 认证<select name="client_auth_method"><option value="basic">HTTP Basic</option><option value="request_body">Request Body</option></select></label>
<button type="submit">保存提供商</button> <button type="button" id="provider-cancel" hidden>取消编辑</button><output id="provider-result" role="status"></output>
</form>
<script>
const csrf = {csrf};
const form = document.querySelector('#provider-form');
const list = document.querySelector('#provider-list');
const result = document.querySelector('#provider-result');
const title = document.querySelector('#provider-form-title');
const cancel = document.querySelector('#provider-cancel');
let providers = [];
function value(name) {{ return form.elements[name].value.trim(); }}
function resetForm() {{
  form.reset();
  form.elements.edit_slug.value = '';
  form.elements.slug.readOnly = false;
  form.elements.client_secret.required = true;
  title.textContent = '添加提供商';
  cancel.hidden = true;
}}
function fillForm(provider) {{
  ['name','slug','authorization_endpoint','token_endpoint','userinfo_endpoint','client_id','scopes','subject_claim','email_claim','name_claim','email_verified_claim','client_auth_method'].forEach((name) => {{
    form.elements[name].value = provider[name] || '';
  }});
  form.elements.edit_slug.value = provider.slug;
  form.elements.slug.readOnly = true;
  form.elements.client_secret.value = '';
  form.elements.client_secret.required = false;
  title.textContent = '编辑提供商';
  cancel.hidden = false;
  window.scrollTo({{top: form.offsetTop, behavior: 'smooth'}});
}}
function addCell(row, text) {{ const cell = document.createElement('td'); cell.textContent = text; row.appendChild(cell); }}
function renderProviders() {{
  list.replaceChildren();
  if (!providers.length) {{ const row = document.createElement('tr'); addCell(row, '暂无自定义 OAuth 提供商'); row.firstChild.colSpan = 6; list.appendChild(row); return; }}
  providers.forEach((provider) => {{
    const row = document.createElement('tr');
    addCell(row, provider.name); addCell(row, provider.slug); addCell(row, provider.callback_uri);
    addCell(row, provider.status === 'active' ? '已启用' : '已停用');
    addCell(row, provider.client_secret_configured ? '已配置' : '未配置');
    const actions = document.createElement('td');
    const edit = document.createElement('button'); edit.type = 'button'; edit.textContent = '编辑'; edit.addEventListener('click', () => fillForm(provider)); actions.appendChild(edit);
    const status = document.createElement('button'); status.type = 'button'; status.textContent = provider.status === 'active' ? '停用' : '启用'; status.addEventListener('click', async () => {{
      const next = provider.status === 'active' ? 'disable' : 'enable';
      const response = await fetch('/api/v1/admin/oauth/providers/' + encodeURIComponent(provider.slug) + '/' + next, {{method: 'POST', headers: {{'X-CSRF-Token': csrf}}}});
      if (response.ok) await loadProviders(); else result.textContent = '状态更新失败。';
    }}); actions.appendChild(document.createTextNode(' ')); actions.appendChild(status); row.appendChild(actions); list.appendChild(row);
  }});
}}
async function loadProviders() {{
  const response = await fetch('/api/v1/admin/oauth/providers');
  if (!response.ok) {{ result.textContent = '提供商列表加载失败。'; return; }}
  providers = await response.json(); renderProviders();
}}
cancel.addEventListener('click', resetForm);
form.addEventListener('submit', async (event) => {{
  event.preventDefault();
  const editSlug = value('edit_slug');
  const input = {{name:value('name'),slug:value('slug'),authorization_endpoint:value('authorization_endpoint'),token_endpoint:value('token_endpoint'),userinfo_endpoint:value('userinfo_endpoint'),client_id:value('client_id'),client_secret:value('client_secret') || null,scopes:value('scopes').split(/\s+/),subject_claim:value('subject_claim'),email_claim:value('email_claim'),name_claim:value('name_claim') || null,email_verified_claim:value('email_verified_claim') || null,client_auth_method:value('client_auth_method')}};
  const response = await fetch(editSlug ? '/api/v1/admin/oauth/providers/' + encodeURIComponent(editSlug) : '/api/v1/admin/oauth/providers', {{method: editSlug ? 'PUT' : 'POST', headers: {{'content-type':'application/json','X-CSRF-Token':csrf}}, body: JSON.stringify(input)}});
  if (response.ok) {{ result.textContent = '保存成功。'; resetForm(); await loadProviders(); }} else result.textContent = '保存失败，请检查配置。';
}});
loadProviders();
</script>
</main>"#,
        csrf = serde_json::to_string(&csrf).expect("CSRF cookie is serializable"),
    );
    Html(web::page("OAuth 提供商设置", &body)).into_response()
}
