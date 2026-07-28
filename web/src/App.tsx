import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { StoreProvider } from "./store";
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

export default function App() {
  return (
    <StoreProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/oauth/authorize" element={<OAuthFlow />} />
          <Route path="/oauth/consent" element={<OAuthConsent />} />
          <Route path="/console" element={<ConsoleLayout />}>
            <Route index element={<Overview />} />
            <Route path="profile" element={<Profile />} />
            <Route path="connections" element={<Connections />} />
            <Route path="developer" element={<Developer />} />
            <Route path="playground" element={<Playground />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </StoreProvider>
  );
}
