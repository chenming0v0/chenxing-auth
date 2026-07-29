import { Navigate } from "react-router-dom";

export default function AdminLogin() {
  return <Navigate to="/login?return_to=%2Fadmin-console" replace />;
}
