import { useCallback, useEffect, useState } from "react";
import { Download, FileClock, LockKeyhole, RefreshCw, FileUp } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { Card, CardContent, CardHeader } from "./components/ui/card";

interface TenantInfo { organizationId: string; role: string; qualificationState: string }
interface Summary { count: number; organizationId: string }
interface DailyCount { dateUtc: string; count: number }
interface DailySummary { organizationId: string; days: DailyCount[] }
interface RegistryItem {
  id: string; issuedUtc: string; digestBase64: string; providerId: string;
  validationState: string;
}
interface AuditItem {
  id: string; organizationId: string; actorSubjectId: string;
  action: "PeriodExportPrepared" | "ReceiptDownloadPrepared";
  occurredUtc: string; receiptId: string | null;
  periodFromUtc: string | null; periodToUtcExclusive: string | null;
}
function utcDateDaysAgo(days: number) {
  const value = new Date();
  value.setUTCDate(value.getUTCDate() - days);
  return value.toISOString().slice(0, 10);
}
function bounds(from: string, to: string) {
  const fromDate = new Date(from + "T00:00:00.000Z");
  const until = new Date(to + "T00:00:00.000Z");
  until.setUTCDate(until.getUTCDate() + 1);
  if (Number.isNaN(fromDate.getTime()) || Number.isNaN(until.getTime()) || fromDate >= until) throw new Error("date");
  const query = new URLSearchParams({ fromUtc: fromDate.toISOString(), toUtcExclusive: until.toISOString() });
  return query;
}

export default function Dashboard({ accessToken }: { accessToken: string }) {
  const { t, i18n } = useTranslation();
  const [from, setFrom] = useState(() => utcDateDaysAgo(29));
  const [to, setTo] = useState(() => utcDateDaysAgo(0));
  const [tenant, setTenant] = useState<TenantInfo | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [daily, setDaily] = useState<DailySummary | null>(null);
  const [dailyRangeTooWide, setDailyRangeTooWide] = useState(false);
  const [records, setRecords] = useState<RegistryItem[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditItem[]>([]);
  const [auditHasMore, setAuditHasMore] = useState(false);
  const [busy, setBusy] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [issueMessage, setIssueMessage] = useState("");
  const [error, setError] = useState("");

  const get = useCallback(async (path: string) => {
    const response = await fetch("/api/v1/" + path, {
      headers: { Authorization: "Bearer " + accessToken },
      cache: "no-store"
    });
    if (!response.ok) throw new Error(response.status === 403 ? t("noTenant") : t("error"));
    return response;
  }, [accessToken, t]);

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const period = bounds(from, to);
      // The daily query deliberately accepts only 1..31 complete UTC days.
      // Longer periods keep the existing full summary/list/audit functional.
      const daySpan = Math.round(
        (Date.parse(to + "T00:00:00.000Z") - Date.parse(from + "T00:00:00.000Z")) / 86_400_000) + 1;
      const showDaily = daySpan >= 1 && daySpan <= 31;
      const [me, count, list, audit, dailyResult] = await Promise.all([
        get("me"), get("stamps/summary?" + period), get("stamps?" + period + "&limit=50"),
        get("audit?" + period + "&limit=20"),
        showDaily ? get("stamps/daily?" + period) : Promise.resolve(null)
      ]);
      setTenant(await me.json() as TenantInfo);
      setSummary(await count.json() as Summary);
      setDaily(dailyResult ? await dailyResult.json() as DailySummary : null);
      setDailyRangeTooWide(!showDaily);
      setRecords(await list.json() as RegistryItem[]);
      const auditPage = await audit.json() as AuditItem[];
      setAuditEvents(auditPage);
      setAuditHasMore(auditPage.length === 20);
    } catch (exception) {
      setDaily(null);
      setDailyRangeTooWide(false);
      setError(exception instanceof Error && exception.message === "date" ? t("dateError") :
        exception instanceof Error ? exception.message : t("error"));
    } finally {
      setBusy(false);
    }
  }, [from, to, get, t]);

  useEffect(() => { void load(); }, [load]);

  const download = async () => {
    setExporting(true);
    setError("");
    try {
      const response = await get("stamps/export?" + bounds(from, to));
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `temporalmark-${from}-${to}.zip`;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      await load();
    } catch (exception) {
      setError(exception instanceof Error ? exception.message : t("error"));
    } finally {
      setExporting(false);
    }
  };

  const downloadReceipt = async (id: string) => {
    setError("");
    try {
      const response = await get(`stamps/${id}/receipt`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `timestamp-${id}.tsr`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      await load();
    } catch (exception) {
      setError(exception instanceof Error ? exception.message : t("error"));
    }
  };

  const issueExternal = async () => {
    if (!selectedFile || issuing) return;
    setIssuing(true);
    setError("");
    setIssueMessage("");
    try {
      // Only the SHA-256 imprint is transmitted. Never upload the original document.
      const imprint = await window.crypto.subtle.digest("SHA-256", await selectedFile.arrayBuffer());
      const base64Digest = btoa(String.fromCharCode(...new Uint8Array(imprint)));
      const response = await fetch("/api/v1/stamps/issue", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + accessToken,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ digestBase64: base64Digest }),
        cache: "no-store"
      });
      if (!response.ok) {
        throw new Error(response.status === 503 ? t("providerNotConfigured") :
          response.status === 403 ? t("noTenant") : t("error"));
      }
      setIssueMessage(t("issueUnverified"));
      setSelectedFile(null);
      await load();
    } catch (exception) {
      setError(exception instanceof Error ? exception.message : t("error"));
    } finally {
      setIssuing(false);
    }
  };

  const loadMoreAudit = async () => {
    setBusy(true);
    setError("");
    try {
      const response = await get("audit?" + bounds(from, to) + "&offset=" + auditEvents.length + "&limit=20");
      const page = await response.json() as AuditItem[];
      setAuditEvents(previous => [...previous, ...page]);
      setAuditHasMore(page.length === 20);
    } catch (exception) {
      setError(exception instanceof Error ? exception.message : t("error"));
    } finally {
      setBusy(false);
    }
  };

  const auditActionLabel = (action: AuditItem["action"]) =>
    action === "PeriodExportPrepared" ? t("auditExportPrepared") : t("auditReceiptPrepared");

  const labelFor = (state: string) => ({
    Unverified: t("unverified"),
    VerifiedNonQualified: t("nonQualified"),
    VerifiedQualifiedExternal: t("qualifiedExternal"),
    VerifiedQualifiedOwn: t("qualifiedOwn"),
    AffectedByIncident: t("affected")
  }[state] ?? t("unverified"));

  return <div className="space-y-6">
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
      <Card><CardHeader><div className="flex items-center gap-2 text-sm text-muted-foreground"><FileClock size={17} /> {t("totals")}</div></CardHeader><CardContent><div className="text-4xl font-bold tabular-nums">{busy ? "…" : (summary ? summary.count.toLocaleString(i18n.language) : "—")}</div></CardContent></Card>
      <Card><CardHeader><div className="flex items-center gap-2 text-sm text-muted-foreground"><LockKeyhole size={17} /> {t("organization")}</div></CardHeader><CardContent><div className="break-all text-sm font-semibold">{tenant?.organizationId ?? "—"}</div><p className="mt-1 text-xs text-muted-foreground">{tenant?.role ?? "—"}</p></CardContent></Card>
      <Card><CardHeader><div className="text-sm text-muted-foreground">{t("technicalStatus")}</div></CardHeader><CardContent><Badge className="text-amber-700 dark:text-amber-300">{t("servicePaused")}</Badge><p className="mt-2 text-xs text-muted-foreground">{tenant?.qualificationState ?? "NOT_QUALIFIED"}</p></CardContent></Card>
    </div>

    <Card>
      <CardHeader><h2 className="text-lg font-semibold">{t("period")}</h2></CardHeader>
      <CardContent>
        <div className="flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-end">
          <label className="flex flex-1 flex-col gap-1 text-sm sm:max-w-48"><span className="text-muted-foreground">{t("from")}</span><input className="h-10 rounded-lg border border-border bg-background px-3" type="date" value={from} onChange={event => setFrom(event.target.value)} /></label>
          <label className="flex flex-1 flex-col gap-1 text-sm sm:max-w-48"><span className="text-muted-foreground">{t("until")}</span><input className="h-10 rounded-lg border border-border bg-background px-3" type="date" value={to} onChange={event => setTo(event.target.value)} /></label>
          <Button variant="outline" disabled={busy} onClick={() => void load()}><RefreshCw size={16} />{t("apply")}</Button>
          <Button disabled={exporting || busy} onClick={() => void download()}><Download size={16} />{exporting ? t("exportBusy") : t("export")}</Button>
        </div>
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">{t("dailyTrend")}</h2>
        <p className="text-xs text-muted-foreground">{t("dailyNotQualified")}</p>
      </CardHeader>
      <CardContent>
        {dailyRangeTooWide ?
          <p className="text-sm text-muted-foreground">{t("dailyRangeLimit")}</p> :
          daily ? <div className="flex gap-2 overflow-x-auto pb-2" role="group" aria-label={t("dailyTrend")}>
            {daily.days.map(day => {
              const highest = Math.max(1, ...daily.days.map(entry => entry.count));
              const barHeight = day.count === 0 ? "2px" :
                Math.max(3, Math.round(day.count / highest * 100)) + "%";
              return <div key={day.dateUtc} className="flex min-w-[32px] flex-1 flex-col items-center gap-1"
                title={day.dateUtc + ": " + day.count}>
                <span className="text-xs tabular-nums">{day.count}</span>
                <div className="relative h-28 w-full rounded-sm bg-muted/40"
                  role="img" aria-label={day.dateUtc + ": " + day.count + " " + t("dailyCountUnit")}>
                  <div className="absolute bottom-0 left-0 right-0 rounded-sm bg-primary"
                    style={{ height: barHeight }} />
                </div>
                <span className="text-[10px] tabular-nums text-muted-foreground">{day.dateUtc.slice(5)}</span>
              </div>;
            })}
          </div> : <p className="text-sm text-muted-foreground">{t("loading")}</p>}
      </CardContent>
    </Card>

    <Card>
      <CardHeader><h2 className="flex items-center gap-2 text-lg font-semibold"><FileUp size={18} />{t("externalTimestamp")}</h2></CardHeader>
      <CardContent className="space-y-4">
        <p className="max-w-3xl text-sm text-muted-foreground">{t("localDigestNotice")}</p>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <label className="flex-1 space-y-1 text-sm">
            <span className="block text-muted-foreground">{t("selectDocument")}</span>
            <input type="file" aria-label={t("selectDocument")} className="block w-full rounded-lg border border-border bg-background p-2 text-sm" onChange={event => {
              setSelectedFile(event.currentTarget.files?.[0] ?? null);
              setIssueMessage("");
            }} />
          </label>
          <Button disabled={!selectedFile || issuing} onClick={() => void issueExternal()}>
            <FileUp size={16} />{issuing ? t("issuing") : t("requestTimestamp")}
          </Button>
        </div>
        {issueMessage && <p role="status" className="text-sm text-foreground">{issueMessage}</p>}
      </CardContent>
    </Card>

    {error && <p role="alert" className="rounded-lg border border-destructive p-3 text-sm text-destructive">{error}</p>}
    <Card>
      <CardHeader><h2 className="text-lg font-semibold">{t("records")}</h2></CardHeader>
      <CardContent>
        {records.length === 0 ? <p className="py-10 text-center text-muted-foreground">{busy ? t("loading") : t("noResults")}</p> :
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead><tr className="border-b border-border text-muted-foreground"><th className="pb-3 font-medium">{t("issued")}</th><th className="pb-3 font-medium">{t("provider")}</th><th className="pb-3 font-medium">{t("digest")}</th><th className="pb-3 font-medium">{t("status")}</th><th className="pb-3 font-medium">{t("actions")}</th></tr></thead>
              <tbody>{records.map(record => <tr className="border-b border-border/50" key={record.id}><td className="py-4 pr-4 whitespace-nowrap">{new Date(record.issuedUtc).toLocaleString(i18n.language, { timeZone: "UTC" })}</td><td className="py-4 pr-4">{record.providerId}</td><td className="max-w-[220px] truncate py-4 pr-4 font-mono text-xs" title={record.digestBase64}>{record.digestBase64}</td><td className="py-4"><Badge>{labelFor(record.validationState)}</Badge></td><td className="py-4"><Button size="sm" variant="outline" aria-label={t("downloadReceipt")} onClick={() => void downloadReceipt(record.id)}><Download size={15} />{t("downloadReceipt")}</Button></td></tr>)}</tbody>
            </table>
          </div>}
        {summary && summary.count > 50 && <p className="mt-4 text-xs text-muted-foreground">50 / {summary.count}</p>}
      </CardContent>
    </Card>
    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">{t("auditHistory")}</h2>
        <p className="text-xs text-muted-foreground">{t("auditDisclaimer")}</p>
      </CardHeader>
      <CardContent>
        {auditEvents.length === 0 ?
          <p className="py-6 text-center text-sm text-muted-foreground">{busy ? t("loading") : t("auditEmpty")}</p> :
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px] text-left text-sm" aria-label={t("auditHistory")}>
              <thead><tr className="border-b border-border text-muted-foreground">
                <th className="pb-3 font-medium">{t("auditWhen")}</th>
                <th className="pb-3 font-medium">{t("auditAction")}</th>
                <th className="pb-3 font-medium">{t("auditActor")}</th>
                <th className="pb-3 font-medium">{t("auditTarget")}</th>
              </tr></thead>
              <tbody>{auditEvents.map(entry =>
                <tr key={entry.id} className="border-b border-border/50">
                  <td className="whitespace-nowrap py-3 pr-4">{new Date(entry.occurredUtc).toLocaleString(i18n.language, { timeZone: "UTC" })}</td>
                  <td className="py-3 pr-4">{auditActionLabel(entry.action)}</td>
                  <td className="break-all py-3 pr-4 font-mono text-xs">{entry.actorSubjectId}</td>
                  <td className="break-all py-3 font-mono text-xs">
                    {entry.receiptId ?? (entry.periodFromUtc && entry.periodToUtcExclusive ?
                      entry.periodFromUtc.slice(0, 10) + " – " + entry.periodToUtcExclusive.slice(0, 10) : "—")}
                  </td>
                </tr>)}</tbody>
            </table>
          </div>}
        {auditHasMore && <Button className="mt-4" disabled={busy} variant="outline" onClick={() => void loadMoreAudit()}>{t("auditMore")}</Button>}
      </CardContent>
    </Card>
  </div>;
}
