import React from "react";
import ReactDOM from "react-dom/client";
import { AuthProvider } from "react-oidc-context";
import App from "./App";
import "./i18n";
import "./index.css";

const origin = window.location.origin;
ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AuthProvider
      authority={import.meta.env.VITE_OIDC_AUTHORITY ?? "http://localhost:8081/realms/temporalmark"}
      client_id="temporalmark-web"
      redirect_uri={origin + "/"}
      post_logout_redirect_uri={origin + "/"}
      response_type="code"
      scope="openid profile email"
      onSigninCallback={() => window.history.replaceState({}, document.title, "/")}
      automaticSilentRenew={false}
    >
      <App />
    </AuthProvider>
  </React.StrictMode>
);
