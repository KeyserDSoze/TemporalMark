import { useCallback, useEffect, useRef, useState } from "react";
import { Download, FileClock, LockKeyhole, RefreshCw, FileUp } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { Card, CardContent, CardHeader } from "./components/ui/card";

interface TenantInfo { organizationId: string; role: string; qualificationState: string }
interface Summary { count: number; organizationId: string }
interface DailyCount { dateUtc: string; count: number }
interface DailySummary { organizationId: string; days: DailyCount[] }
interface ImprintSearchPage {
  items: RegistryItem[];
  hasMore: boolean;
}
interface ImprintSearchView extends ImprintSearchPage {
  offset: number;
  hex: string;
  token: string;
  from: string;
  to: string;
}
interface RegistryItem {
  id: string; issuedUtc: string; digestBase64: string; providerId: string;
  validationState: string;
}
interface AuditItem {
  id: string; organizationId: string; actorSubjectId: string;
  action: "PeriodExportPrepared" | "ReceiptDownloadPrepared" | "DocumentImprintSearchPerformed";
  occurredUtc: string; receiptId: string | null;
  periodFromUtc: string | null; periodToUtcExclusive: string | null;
}
const REGISTRY_PAGE_SIZE = 50;

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
  const [registryOffset, setRegistryOffset] = useState(0);
  // Results are only renderable under the access token which fetched them.
  // The monotonically increasing generation prevents older async requests
  // (old dates/page/token) from overwriting a later, authorized response.
  const [loadedToken, setLoadedToken] = useState<string | null>(null);
  const loadGeneration = useRef(0);
  const [auditEvents, setAuditEvents] = useState<AuditItem[]>([]);
  const [auditHasMore, setAuditHasMore] = useState(false);
  const [busy, setBusy] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [issueMessage, setIssueMessage] = useState("");
  const [searchHex, setSearchHex] = useState("");
  const [searchState, setSearchState] = useState<ImprintSearchView | null>(null);
  const [searchBusy, setSearchBusy] = useState(false);
  const [searchError, setSearchError] = useState("");
  const searchGeneration = useRef(0);
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
    const generation = ++loadGeneration.current;
    setBusy(true);
    setLoadedToken(null); // never display a previous period or session while loading
    setError("");
    try {
      const period = bounds(from, to);
      // Only 1..31 complete UTC days are allowed for the *optional* chart.
      // The exact total, registry list, audit and ZIP remain available.
      const daySpan = Math.round(
        (Date.parse(to + "T00:00:00.000Z") - Date.parse(from + "T00:00:00.000Z")) / 86_400_000) + 1;
      const showDaily = daySpan >= 1 && daySpan <= 31;
      const [me, count, list, audit, dailyResult] = await Promise.all([
        get("me"), get("stamps/summary?" + period),
        get("stamps?" + period + "&offset=" + registryOffset + "&limit=" + REGISTRY_PAGE_SIZE),
        get("audit?" + period + "&limit=20"),
        showDaily ? get("stamps/daily?" + period) : Promise.resolve(null)
      ]);
      const [nextTenant, nextSummary, nextRecords, nextAudit, nextDaily] = await Promise.all([
        me.json() as Promise<TenantInfo>, count.json() as Promise<Summary>,
        list.json() as Promise<RegistryItem[]>, audit.json() as Promise<AuditItem[]>,
        dailyResult ? dailyResult.json() as Promise<DailySummary> : Promise.resolve(null)
      ]);
      if (generation !== loadGeneration.current) return;
      if (nextTenant.organizationId !== nextSummary.organizationId ||
          (nextDaily && nextDaily.organizationId !== nextTenant.organizationId) ||
          !Number.isSafeInteger(nextSummary.count) || nextSummary.count < 0 ||
          !Array.isArray(nextRecords) || nextRecords.length > REGISTRY_PAGE_SIZE ||
          !Array.isArray(nextAudit) || nextAudit.length > 20)
        throw new Error(t("error"));
      // Commit the whole batch at once. Never mix two date/token/page views.
      setTenant(nextTenant);
      setSummary(nextSummary);
      setDaily(nextDaily);
      setDailyRangeTooWide(!showDaily);
      setRecords(nextRecords);
      setAuditEvents(nextAudit);
      setAuditHasMore(nextAudit.length === 20);
      setLoadedToken(accessToken);
    } catch (exception) {
      if (generation !== loadGeneration.current) return;
      setTenant(null);
      setSummary(null);
      setDaily(null);
      setRecords([]);
      setAuditEvents([]);
      setAuditHasMore(false);
      setDailyRangeTooWide(false);
      setLoadedToken(null);
      setError(exception instanceof Error && exception.message === "date" ? t("dateError") :
        exception instanceof Error ? exception.message : t("error"));
    } finally {
      if (generation === loadGeneration.current) setBusy(false);
    }
  }, [from, to, registryOffset, accessToken, get, t]);

  useEffect(() => {
    // Invalidate requests on effect cleanup, including logout/unmount.
    void load();
    return () => { loadGeneration.current += 1; };
  }, [load]);

  useEffect(() => {
    setRegistryOffset(0);
    setSelectedFile(null);
    setIssueMessage("");
  }, [accessToken]);

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

  // Search uses a read-only authenticated POST so a sensitive document
  // fingerprint is never embedded in URL/query logs or browser history.
  // It is distinct from the default period registry list and count.
  const searchImprint = async (offset: number) => {
    if (!/^[0-9A-Fa-f]{64}$/.test(searchHex) || offset < 0) return;
    const generation = ++searchGeneration.current;
    const hex = searchHex;
    const token = accessToken;
    const requestedFrom = from;
    const requestedTo = to;
    setSearchBusy(true);
    setSearchError("");
    setSearchState(null);
    try {
      const period = bounds(requestedFrom, requestedTo);
      const response = await fetch("/api/v1/stamps/search", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + token,
          "Content-Type": "application/json"
        },
        cache: "no-store",
        body: JSON.stringify({
          fromUtc: period.get("fromUtc"),
          toUtcExclusive: period.get("toUtcExclusive"),
          digestSha256Hex: hex,
          offset,
          limit: REGISTRY_PAGE_SIZE
        })
      });
      if (!response.ok) throw new Error(response.status === 403 ? t("noTenant") : t("error"));
      const payload = await response.json() as ImprintSearchPage;
      if (generation !== searchGeneration.current) return;
      if (!payload || !Array.isArray(payload.items) ||
          payload.items.length > REGISTRY_PAGE_SIZE ||
          typeof payload.hasMore !== "boolean" ||
          new Set(payload.items.map(item => item.id)).size !== payload.items.length)
        throw new Error(t("error"));
      setSearchState({ ...payload, offset, hex, token, from: requestedFrom, to: requestedTo });
    } catch (exception) {
      if (generation !== searchGeneration.current) return;
      setSearchState(null);
      setSearchError(exception instanceof Error ? exception.message : t("error"));
    } finally {
      if (generation === searchGeneration.current) setSearchBusy(false);
    }
  };

  useEffect(() => {
    // A changing UTC period or identity immediately makes a previous
    // search page ineligible for rendering. In-flight old replies are ignored.
    searchGeneration.current += 1;
    setSearchState(null);
    setSearchError("");
    setSearchBusy(false);
  }, [from, to, accessToken]);

  const loadMoreAudit = async () => {
    const generation = loadGeneration.current;
    setBusy(true);
    setError("");
    try {
      const response = await get("audit?" + bounds(from, to) + "&offset=" + auditEvents.length + "&limit=20");
      const page = await response.json() as AuditItem[];
      if (generation !== loadGeneration.current) return;
      setAuditEvents(previous => [...previous, ...page]);
      setAuditHasMore(page.length === 20);
    } catch (exception) {
      if (generation === loadGeneration.current)
        setError(exception instanceof Error ? exception.message : t("error"));
    } finally {
      if (generation === loadGeneration.current) setBusy(false);
    }
  };

  const auditActionLabel = (action: AuditItem["action"]) =>
    action === "PeriodExportPrepared" ? t("auditExportPrepared")
      : action === "ReceiptDownloadPrepared" ? t("auditReceiptPrepared")
      : t("auditImprintSearchPerformed");

  const labelFor = (state: string) => ({
    Unverified: t("unverified"),
    VerifiedNonQualified: t("nonQualified"),
    VerifiedQualifiedExternal: t("qualifiedExternal"),
    VerifiedQualifiedOwn: t("qualifiedOwn"),
    AffectedByIncident: t("affected")
  }[state] ?? t("unverified"));

  const sessionReady = loadedToken === accessToken;
  const currentSearch = searchState &&
    searchState.token === accessToken &&
    searchState.from === from && searchState.to === to &&
    searchState.hex === searchHex && sessionReady ? searchState : null;
  const currentTenant = sessionReady ? tenant : null;
  const currentSummary = sessionReady ? summary : null;
  const currentDaily = sessionReady ? daily : null;
  const currentDailyRangeTooWide = sessionReady && dailyRangeTooWide;
  const currentRecords = sessionReady ? records : [];
  const currentAuditEvents = sessionReady ? auditEvents : [];
  const currentAuditHasMore = sessionReady && auditHasMore;

  return <div className="space-y-6">
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
      <Card><CardHeader><div className="flex items-center gap-2 text-sm text-muted-foreground"><FileClock size={17} /> {t("totals")}</div></CardHeader><CardContent><div className="text-4xl font-bold tabular-nums">{busy ? "…" : (currentSummary ? currentSummary.count.toLocaleString(i18n.language) : "—")}</div></CardContent></Card>
      <Card><CardHeader><div className="flex items-center gap-2 text-sm text-muted-foreground"><LockKeyhole size={17} /> {t("organization")}</div></CardHeader><CardContent><div className="break-all text-sm font-semibold">{currentTenant?.organizationId ?? "—"}</div><p className="mt-1 text-xs text-muted-foreground">{currentTenant?.role ?? "—"}</p></CardContent></Card>
      <Card><CardHeader><div className="text-sm text-muted-foreground">{t("technicalStatus")}</div></CardHeader><CardContent><Badge className="text-amber-700 dark:text-amber-300">{t("servicePaused")}</Badge><p className="mt-2 text-xs text-muted-foreground">{currentTenant?.qualificationState ?? "NOT_QUALIFIED"}</p></CardContent></Card>
    </div>

    <Card>
      <CardHeader><h2 className="text-lg font-semibold">{t("period")}</h2></CardHeader>
      <CardContent>
        <div className="flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-end">
          <label className="flex flex-1 flex-col gap-1 text-sm sm:max-w-48"><span className="text-muted-foreground">{t("from")}</span><input className="h-10 rounded-lg border border-border bg-background px-3" type="date" value={from} onChange={event => { setFrom(event.target.value); setRegistryOffset(0); setLoadedToken(null); }} /></label>
          <label className="flex flex-1 flex-col gap-1 text-sm sm:max-w-48"><span className="text-muted-foreground">{t("until")}</span><input className="h-10 rounded-lg border border-border bg-background px-3" type="date" value={to} onChange={event => { setTo(event.target.value); setRegistryOffset(0); setLoadedToken(null); }} /></label>
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
        {currentDailyRangeTooWide ?
          <p className="text-sm text-muted-foreground">{t("dailyRangeLimit")}</p> :
          currentDaily ? <div className="flex gap-2 overflow-x-auto pb-2" role="group" aria-label={t("dailyTrend")}>
            {currentDaily.days.map(day => {
              const highest = Math.max(1, ...currentDaily.days.map(entry => entry.count));
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
        {currentRecords.length === 0 ? <p className="py-10 text-center text-muted-foreground">{busy ? t("loading") : t("noResults")}</p> :
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead><tr className="border-b border-border text-muted-foreground"><th className="pb-3 font-medium">{t("issued")}</th><th className="pb-3 font-medium">{t("provider")}</th><th className="pb-3 font-medium">{t("digest")}</th><th className="pb-3 font-medium">{t("status")}</th><th className="pb-3 font-medium">{t("actions")}</th></tr></thead>
              <tbody>{currentRecords.map(record => <tr className="border-b border-border/50" key={record.id}><td className="py-4 pr-4 whitespace-nowrap">{new Date(record.issuedUtc).toLocaleString(i18n.language, { timeZone: "UTC" })}</td><td className="py-4 pr-4">{record.providerId}</td><td className="max-w-[220px] truncate py-4 pr-4 font-mono text-xs" title={record.digestBase64}>{record.digestBase64}</td><td className="py-4"><Badge>{labelFor(record.validationState)}</Badge></td><td className="py-4"><Button size="sm" variant="outline" aria-label={t("downloadReceipt")} onClick={() => void downloadReceipt(record.id)}><Download size={15} />{t("downloadReceipt")}</Button></td></tr>)}</tbody>
            </table>
          </div>}
        {currentSummary && (currentSummary.count > REGISTRY_PAGE_SIZE || registryOffset > 0) &&
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
            <p role="status" className="text-xs tabular-nums text-muted-foreground">
              {t("registryPageStatus", {
                start: currentRecords.length > 0 ? registryOffset + 1 : 0,
                end: registryOffset + currentRecords.length,
                total: currentSummary.count
              })}
            </p>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={busy || registryOffset === 0}
                onClick={() => setRegistryOffset(value => Math.max(0, value - REGISTRY_PAGE_SIZE))}>
                {t("registryPrevious")}
              </Button>
              <Button variant="outline" size="sm"
                disabled={busy || currentRecords.length < REGISTRY_PAGE_SIZE ||
                  registryOffset + currentRecords.length >= currentSummary.count}
                onClick={() => setRegistryOffset(value => value + REGISTRY_PAGE_SIZE)}>
                {t("registryNext")}
              </Button>
            </div>
          </div>}
      </CardContent>
    </Card>
    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">{t("searchImprintHeading")}</h2>
        <p className="text-xs text-muted-foreground">{t("searchImprintHelp")}</p>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <label className="flex flex-1 flex-col gap-1 text-sm">
            <span className="text-muted-foreground">{t("searchImprintLabel")}</span>
            <input type="text" inputMode="text" spellCheck={false} autoComplete="off"
              maxLength={64} value={searchHex}
              aria-label={t("searchImprintLabel")}
              className="h-10 w-full rounded-lg border border-border bg-background px-3 font-mono text-xs"
              onChange={event => {
                searchGeneration.current += 1;
                setSearchHex(event.target.value);
                setSearchState(null);
                setSearchError("");
                setSearchBusy(false);
              }} />
          </label>
          <Button variant="outline" disabled={!sessionReady || searchBusy ||
              !/^[0-9A-Fa-f]{64}$/.test(searchHex)}
            onClick={() => void searchImprint(0)}>
            {searchBusy ? t("loading") : t("searchImprintButton")}
          </Button>
        </div>
        {searchError && <p role="alert" className="text-sm text-destructive">{searchError}</p>}
        {currentSearch && <>
          {currentSearch.items.length === 0 ?
            <p className="text-sm text-muted-foreground">{t("searchImprintNoResults")}</p> :
            <div className="overflow-x-auto">
              <table className="w-full min-w-[580px] text-left text-sm" aria-label={t("searchImprintHeading")}>
                <thead><tr className="border-b border-border text-muted-foreground">
                  <th className="pb-3 font-medium">{t("issued")}</th>
                  <th className="pb-3 font-medium">{t("provider")}</th>
                  <th className="pb-3 font-medium">{t("status")}</th>
                  <th className="pb-3 font-medium">{t("actions")}</th>
                </tr></thead>
                <tbody>{currentSearch.items.map(item =>
                  <tr key={item.id} className="border-b border-border/50">
                    <td className="py-3 pr-4 whitespace-nowrap">
                      {new Date(item.issuedUtc).toLocaleString(i18n.language, { timeZone: "UTC" })}
                    </td>
                    <td className="py-3 pr-4">{item.providerId}</td>
                    <td className="py-3 pr-4"><Badge>{labelFor(item.validationState)}</Badge></td>
                    <td className="py-3"><Button size="sm" variant="outline"
                      onClick={() => void downloadReceipt(item.id)}>{t("downloadReceipt")}</Button></td>
                  </tr>)}</tbody>
              </table>
            </div>}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p role="status" className="text-xs text-muted-foreground">
              {t("searchImprintPageStatus", {
                start: currentSearch.items.length > 0 ? currentSearch.offset + 1 : 0,
                end: currentSearch.offset + currentSearch.items.length
              })}
            </p>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" disabled={searchBusy || currentSearch.offset === 0}
                onClick={() => void searchImprint(Math.max(0, currentSearch.offset - REGISTRY_PAGE_SIZE))}>
                {t("searchImprintPrevious")}
              </Button>
              <Button size="sm" variant="outline" disabled={searchBusy || !currentSearch.hasMore}
                onClick={() => void searchImprint(currentSearch.offset + REGISTRY_PAGE_SIZE)}>
                {t("searchImprintNext")}
              </Button>
            </div>
          </div>
        </>}
      </CardContent>
    </Card>
    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">{t("auditHistory")}</h2>
        <p className="text-xs text-muted-foreground">{t("auditDisclaimer")}</p>
      </CardHeader>
      <CardContent>
        {currentAuditEvents.length === 0 ?
          <p className="py-6 text-center text-sm text-muted-foreground">{busy ? t("loading") : t("auditEmpty")}</p> :
          <div className="overflow-x-auto">
            <table className="w-full min-w-[620px] text-left text-sm" aria-label={t("auditHistory")}>
              <thead><tr className="border-b border-border text-muted-foreground">
                <th className="pb-3 font-medium">{t("auditWhen")}</th>
                <th className="pb-3 font-medium">{t("auditAction")}</th>
                <th className="pb-3 font-medium">{t("auditActor")}</th>
                <th className="pb-3 font-medium">{t("auditTarget")}</th>
              </tr></thead>
              <tbody>{currentAuditEvents.map(entry =>
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
        {currentAuditHasMore && <Button className="mt-4" disabled={busy} variant="outline" onClick={() => void loadMoreAudit()}>{t("auditMore")}</Button>}
      </CardContent>
    </Card>
  </div>;
}
