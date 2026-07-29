import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { api, errorMessage } from "./api";
import { StoreProvider } from "./store";
import { GlowButton } from "./components/ui";
import Bootstrap from "./pages/Bootstrap";
import Landing from "./pages/Landing";
import { Login, Register } from "./pages/Auth";
import OAuthFlow from "./pages/OAuthFlow";
import ConsoleLayout from "./pages/console/ConsoleLayout";
import Overview from "./pages/console/Overview";
import Profile from "./pages/console/Profile";
import Connections from "./pages/console/Connections";
import Developer from "./pages/console/Developer";
import Playground from "./pages/console/Playground";
import OAuthConsent from "./pages/OAuthConsent";
import AdminLogin from "./pages/AdminLogin";
import AdminConsoleLayout from "./pages/AdminConsoleLayout";
import AdminSettings from "./pages/AdminSettings";

export default function App() {
  return (
    <StoreProvider>
      <BrowserRouter>
        <BootstrapGate />
      </BrowserRouter>
    </StoreProvider>
  );
}

function BootstrapGate() {
  const [initialized, setInitialized] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  const checkStatus = () => {
    setError(null);
    setInitialized(null);
    void api.bootstrapStatus()
      .then((status) => setInitialized(status.initialized))
      .catch((value) => setError(errorMessage(value)));
  };

  useEffect(() => { checkStatus(); }, []);

  if (initialized === null && !error) return <GateLoading />;
  if (error) return <GateError message={error} onRetry={checkStatus} />;
  if (!initialized) return <Bootstrap onComplete={() => { setInitialized(true); window.location.assign("/login?return_to=%2Fadmin-console"); }} />;

  return <Routes>
    <Route path="/" element={<Landing />} />
    <Route path="/login" element={<Login />} />
    <Route path="/register" element={<Register />} />
    <Route path="/oauth/authorize" element={<OAuthFlow />} />
    <Route path="/oauth/consent" element={<OAuthConsent />} />
    <Route path="/admin-console/login" element={<AdminLogin />} />
    <Route path="/admin-console" element={<AdminConsoleLayout />}>
      <Route index element={<Navigate to="settings" replace />} />
      <Route path="settings" element={<AdminSettings />} />
    </Route>
    <Route path="/console" element={<ConsoleLayout />}>
      <Route index element={<Overview />} />
      <Route path="profile" element={<Profile />} />
      <Route path="connections" element={<Connections />} />
      <Route path="developer" element={<Developer />} />
      <Route path="playground" element={<Playground />} />
    </Route>
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>;
}

function GateLoading() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-app text-xs text-slate-500">
      正在准备辰星认证中枢…
    </div>
  );
}

function GateError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-app p-6">
      <div className="panel w-full max-w-md rounded-xl px-6 py-10 text-center">
        <h1 className="text-base font-semibold text-white">无法检查初始化状态</h1>
        <p className="mt-2 text-xs leading-relaxed text-slate-500">{message}</p>
        <GlowButton className="mt-6" onClick={onRetry}>重新检查</GlowButton>
      </div>
    </div>
  );
}
