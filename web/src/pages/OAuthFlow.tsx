import { Link } from "react-router-dom";
import { ArrowLeft, FlaskConical, ShieldCheck } from "lucide-react";
import { GhostButton, Logo } from "../components/ui";

/**
 * `/oauth/authorize` is served by the backend, so React only renders this when
 * someone lands on the SPA route directly with no authorization request.
 */
export default function OAuthFlow() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-app p-6">
      <div className="panel w-full max-w-md rounded-xl px-6 py-10 text-center">
        <Logo size={32} className="mx-auto" />
        <div className="mt-6 flex justify-center">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-white/[0.04] text-slate-400">
            <ShieldCheck size={20} />
          </span>
        </div>
        <h1 className="mt-4 text-base font-semibold text-white">这里没有待处理的授权请求</h1>
        <p className="mt-2 text-xs leading-relaxed text-slate-500">
          授权流程由服务端的授权端点处理，包括登录、授权确认、PKCE 校验和回调。
          要发起一次真实流程，请从授权测试页构造请求。
        </p>
        <div className="mt-6 flex justify-center gap-2.5">
          <Link to="/console/playground">
            <GhostButton><FlaskConical size={14} /> 授权测试</GhostButton>
          </Link>
          <Link to="/">
            <GhostButton><ArrowLeft size={14} /> 返回首页</GhostButton>
          </Link>
        </div>
      </div>
    </div>
  );
}
