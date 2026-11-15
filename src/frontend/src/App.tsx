import { useEffect, useState } from "react";
import { Clock3, Globe2, LogOut, Moon, ShieldAlert, Sun } from "lucide-react";
import { useAuth } from "react-oidc-context";
import { useTranslation } from "react-i18next";
import { Button } from "./components/ui/button";
import { Badge } from "./components/ui/badge";
import Dashboard from "./Dashboard";

export default function App() {
  const { t, i18n } = useTranslation();
  const auth = useAuth();
  const [dark, setDark] = useState(() => localStorage.getItem("temporalmark-theme") === "dark");

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem("temporalmark-theme", dark ? "dark" : "light");
  }, [dark]);

  const setLanguage = (lang: "it" | "en") => {
    void i18n.changeLanguage(lang);
    localStorage.setItem("temporalmark-language", lang);
    document.documentElement.lang = lang;
  };

  return <div className="min-h-screen bg-background text-foreground">
    <header className="border-b border-border bg-card/80">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-4 sm:px-8">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-600 text-white"><Clock3 size={22} /></div>
          <div><div className="text-lg font-extrabold tracking-tight">TemporalMark</div><div className="text-xs text-muted-foreground">{t("tagline")}</div></div>
        </div>
        <div className="flex items-center gap-1.5">
          <Globe2 aria-hidden="true" size={17} className="mr-1 text-muted-foreground" />
          <Button aria-label="Italiano" variant={i18n.language === "it" ? "default" : "ghost"} size="sm" onClick={() => setLanguage("it")}>IT</Button>
          <Button aria-label="English" variant={i18n.language === "en" ? "default" : "ghost"} size="sm" onClick={() => setLanguage("en")}>EN</Button>
          <Button variant="ghost" size="icon" aria-label={dark ? t("light") : t("dark")} onClick={() => setDark(!dark)}>{dark ? <Sun size={19} /> : <Moon size={19} />}</Button>
          {auth.isAuthenticated && <Button variant="outline" size="sm" onClick={() => void auth.signoutRedirect()}><LogOut size={15} /> <span className="hidden sm:inline">{t("logout")}</span></Button>}
        </div>
      </div>
    </header>

    <main className="mx-auto max-w-6xl px-4 py-8 sm:px-8 sm:py-12">
      <div className="mb-8 flex flex-col gap-3">
        <Badge className="w-fit border-amber-400/40 bg-amber-100 text-amber-950 dark:bg-amber-900/30 dark:text-amber-200"><ShieldAlert size={13} className="mr-1" />{t("qualificationWarning")}</Badge>
        <h1 className="text-3xl font-extrabold tracking-tight sm:text-4xl">{t("dashboard")}</h1>
        <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground sm:text-base">{t("intro")}</p>
      </div>
      {auth.isLoading ? <p role="status">{t("loading")}</p>
      : auth.error ? <p role="alert" className="text-destructive">{auth.error.message}</p>
      : !auth.isAuthenticated ? <div className="rounded-xl border border-border bg-card p-8 sm:p-12"><Button onClick={() => void auth.signinRedirect()}>{t("login")}</Button></div>
      : <Dashboard accessToken={auth.user?.access_token ?? ""} />}
    </main>
    <footer className="mx-auto max-w-6xl px-4 pb-8 text-xs text-muted-foreground sm:px-8">{t("verification")}</footer>
  </div>;
}
