import { Link } from "react-router-dom";
import { ArrowLeft, ExternalLink, ShieldCheck } from "lucide-react";
import { GhostButton, Logo } from "../components/ui";

export default function OAuthFlow() { return <div className="flex min-h-screen items-center justify-center bg-[#05060f] p-6"><div className="glass w-full max-w-lg rounded-3xl p-8 text-center"><Logo size={48} /><ShieldCheck size={30} className="mx-auto mt-6 text-emerald-300" /><h1 className="mt-5 text-xl font-bold text-white">OAuth 授权由认证端点处理</h1><p className="mt-2 text-sm leading-7 text-slate-500">请从开发者测试台生成真实的授权请求，服务端会负责登录、授权确认、PKCE 校验和回调。</p><div className="mt-6 flex justify-center gap-3"><Link to="/console/playground"><GhostButton><ExternalLink size={14} className="mr-1.5 inline" />打开测试台</GhostButton></Link><Link to="/"><GhostButton><ArrowLeft size={14} className="mr-1.5 inline" />返回首页</GhostButton></Link></div></div></div>; }
