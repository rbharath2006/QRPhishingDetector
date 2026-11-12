(() => {
    "use strict";

    const HISTORY_KEY = "qrUnifiedReports";
    const MAX_HISTORY = 10;

    const escapeText = (value) => {
        if (value === null || value === undefined || value === "") {
            return "Not available";
        }
        return String(value);
    };

    function normalizeInput(raw) {
        let value = String(raw || "").trim();

        if (!value) {
            throw new Error("Enter a URL to analyse.");
        }

        if (!/^https?:\/\//i.test(value)) {
            value = `https://${value}`;
        }

        let url;

        try {
            url = new URL(value);
        } catch {
            throw new Error("Enter a valid HTTP or HTTPS URL.");
        }

        if (!["http:", "https:"].includes(url.protocol)) {
            throw new Error("Only HTTP and HTTPS URLs are supported.");
        }

        if (!url.hostname || url.username || url.password) {
            throw new Error(
                "The URL must have a hostname and must not contain embedded credentials."
            );
        }

        if (url.href.length > 2048) {
            throw new Error("The URL must not exceed 2048 characters.");
        }

        return url.href;
    }

    async function postJson(path, payload) {
        const response = await fetch(path, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify(payload)
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            const error = new Error(
                data.error ||
                data.detail ||
                data.message ||
                `Request failed (HTTP ${response.status}).`
            );

            error.status = response.status;
            error.payload = data;
            throw error;
        }

        return data;
    }

    function getHistory() {
        try {
            const parsed = JSON.parse(
                localStorage.getItem(HISTORY_KEY) || "[]"
            );

            return Array.isArray(parsed) ? parsed : [];
        } catch {
            return [];
        }
    }

    function saveSummary(report) {
        // Store report metadata only. Do not save screenshots or page text.
        const entry = {
            createdAt: new Date().toISOString(),
            url: report.inputUrl,
            destination: report.destination || "",
            riskScore: report.primaryThreat?.riskScore ?? "",
            verdict: report.primaryThreat?.verdict ?? "",
            knownThreatMatch: Boolean(
                report.primaryThreat?.knownThreatMatch
            ),
            redirectStatus: report.redirect?.status || "NOT_RUN",
            sandboxStatus: report.sandbox?.status || "NOT_RUN",
            pageTitle: report.sandbox?.data?.pageTitle || "",
            httpStatus: report.sandbox?.data?.httpStatus ?? "",
            requestsObserved:
                report.sandbox?.data?.requestCountRecorded ??
                report.sandbox?.data?.requests?.length ??
                ""
        };

        try {
            const history = getHistory();

            history.unshift(entry);

            localStorage.setItem(
                HISTORY_KEY,
                JSON.stringify(history.slice(0, MAX_HISTORY))
            );
        } catch {
            // The current report remains viewable if storage is unavailable.
        }
    }

    function csvCell(value) {
        const text = value === null || value === undefined
            ? ""
            : String(value);

        return `"${text.replace(/"/g, '""')}"`;
    }

    function exportHistory() {
        const history = getHistory();

        if (!history.length) {
            window.alert("No unified reports are saved yet.");
            return;
        }

        const columns = [
            "createdAt",
            "url",
            "destination",
            "riskScore",
            "verdict",
            "knownThreatMatch",
            "redirectStatus",
            "sandboxStatus",
            "pageTitle",
            "httpStatus",
            "requestsObserved"
        ];

        const csv = [
            columns.join(","),
            ...history.map(row =>
                columns.map(column => csvCell(row[column])).join(",")
            )
        ].join("\r\n");

        const blob = new Blob(
            ["\uFEFF", csv],
            { type: "text/csv;charset=utf-8" }
        );

        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");

        link.href = objectUrl;
        link.download = "qr-unified-analysis-reports.csv";

        document.body.appendChild(link);
        link.click();
        link.remove();

        URL.revokeObjectURL(objectUrl);
    }

    function install() {
        if (document.getElementById("unified-threat-report-panel")) {
            return;
        }

        const panel = document.createElement("section");
        panel.id = "unified-threat-report-panel";

        panel.style.cssText = [
            "grid-column:1/-1",
            "width:100%",
            "box-sizing:border-box",
            "margin:20px 0",
            "padding:24px",
            "border:1px solid #374151",
            "border-radius:14px",
            "background:#0b1220",
            "color:#e5e7eb",
            "font-family:inherit"
        ].join(";");

        // User-controlled and API-provided values are rendered using textContent.
        panel.innerHTML = `
      <h2 style="margin-top:0">
        Unified Threat Analysis Report
      </h2>

      <p style="color:#cbd5e1;max-width:900px">
        Combine local threat-intelligence checks with optional
        short-link resolution and isolated browser observations.
        The risk score comes from the local detection engine;
        browser and redirect observations are separate evidence,
        not proof of safety or maliciousness.
      </p>

      <form id="unified-report-form">
        <label
          for="unified-report-url"
          style="display:block;font-weight:600;margin-bottom:8px"
        >
          URL to analyse
        </label>

        <div style="display:flex;flex-wrap:wrap;gap:10px">
          <input
            id="unified-report-url"
            name="url"
            type="text"
            maxlength="2048"
            required
            placeholder="https://example.com/"
            autocomplete="url"
            style="flex:1;min-width:240px;padding:12px;border:1px solid #4b5563;border-radius:8px;background:#030712;color:#f9fafb"
          >

          <button
            id="unified-report-submit"
            type="submit"
            style="padding:12px 18px;border:0;border-radius:8px;background:#2563eb;color:#fff;font-weight:700;cursor:pointer"
          >
            Generate Unified Report
          </button>
        </div>

        <div style="display:flex;flex-wrap:wrap;gap:18px;margin-top:12px">
          <label style="display:flex;gap:8px;align-items:center">
            <input id="unified-report-redirect" type="checkbox">
            Attempt short-link resolution
          </label>

          <label style="display:flex;gap:8px;align-items:center">
            <input
              id="unified-report-sandbox"
              type="checkbox"
              checked
            >
            Run browser sandbox (HTTPS, standard port only)
          </label>
        </div>
      </form>

      <p id="unified-report-status" role="status" aria-live="polite">
        Ready. Enter a URL to generate a report.
      </p>

      <div id="unified-report-results" hidden>
        <h3>Threat intelligence</h3>

        <div
          id="unified-report-threat-summary"
          style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px"
        ></div>

        <details style="margin-top:12px">
          <summary>Threat matches and explanations</summary>
          <pre
            id="unified-report-threat-details"
            style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto"
          ></pre>
        </details>

        <h3>Redirect evidence</h3>

        <pre
          id="unified-report-redirect-details"
          style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:240px;overflow:auto;padding:12px;background:#030712;border-radius:8px"
        ></pre>

        <h3>Browser sandbox evidence</h3>

        <div
          id="unified-report-sandbox-summary"
          style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px"
        ></div>

        <p
          id="unified-report-sandbox-limitations"
          style="color:#cbd5e1"
        ></p>

        <details style="margin-top:12px">
          <summary>Browser observations</summary>
          <pre
            id="unified-report-sandbox-details"
            style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto"
          ></pre>
        </details>

        <details style="margin-top:12px">
          <summary>Visible page text sample</summary>
          <pre
            id="unified-report-sandbox-text"
            style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:220px;overflow:auto"
          ></pre>
        </details>

        <div
          id="unified-report-screenshot-wrap"
          hidden
          style="margin-top:12px"
        >
          <h3>Sandbox screenshot</h3>
          <img
            id="unified-report-screenshot"
            alt="Screenshot captured by the isolated browser"
            style="display:block;max-width:100%;max-height:600px;border:1px solid #374151;border-radius:8px"
          >
        </div>

        <p style="margin-top:16px;color:#fbbf24">
          <strong>Interpretation:</strong>
          A low score, no local indicator match, successful HTTP
          response, or clean browser observation does not guarantee
          that a URL is safe. Check the source, freshness and coverage
          of evidence.
        </p>
      </div>

      <hr
        style="border:0;border-top:1px solid #374151;margin:22px 0"
      >

      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <h3 style="margin:0">Recent unified reports</h3>

        <button
          id="unified-report-export"
          type="button"
          style="padding:9px 12px;border:1px solid #4b5563;border-radius:8px;background:#111827;color:#e5e7eb;cursor:pointer"
        >
          Export reports as CSV
        </button>
      </div>

      <div
        id="unified-report-history"
        style="margin-top:12px"
      ></div>
    `;

        const host =
            document.querySelector(".dashboard-grid") ||
            document.querySelector("main") ||
            document.body;

        const sandboxPanel =
            document.getElementById("sandbox-analysis-panel");

        if (
            sandboxPanel &&
            sandboxPanel.parentElement === host
        ) {
            sandboxPanel.insertAdjacentElement("afterend", panel);
        } else {
            host.appendChild(panel);
        }

        const byId = (id) => panel.querySelector(`#${id}`);

        const form = byId("unified-report-form");
        const urlInput = byId("unified-report-url");
        const submit = byId("unified-report-submit");
        const status = byId("unified-report-status");
        const results = byId("unified-report-results");

        function setText(id, value) {
            byId(id).textContent = escapeText(value);
        }

        function renderCards(containerId, rows) {
            const container = byId(containerId);

            container.replaceChildren();

            for (const [label, value] of rows) {
                const card = document.createElement("div");

                card.style.cssText =
                    "padding:12px;border:1px solid #374151;border-radius:8px;min-width:0";

                const term = document.createElement("div");
                term.textContent = label;
                term.style.cssText =
                    "font-weight:700;color:#93c5fd;margin-bottom:5px";

                const description = document.createElement("div");
                description.textContent = escapeText(value);
                description.style.cssText = "overflow-wrap:anywhere";

                card.append(term, description);
                container.appendChild(card);
            }
        }

        function renderHistory() {
            const container = byId("unified-report-history");

            container.replaceChildren();

            const history = getHistory();

            if (!history.length) {
                const empty = document.createElement("p");
                empty.textContent =
                    "No unified reports have been saved in this browser yet.";
                empty.style.color = "#9ca3af";

                container.appendChild(empty);
                return;
            }

            for (const item of history) {
                const row = document.createElement("div");

                row.style.cssText =
                    "display:grid;grid-template-columns:minmax(0,2fr) minmax(120px,1fr);gap:8px;padding:12px 0;border-bottom:1px solid #374151";

                const left = document.createElement("div");

                const url = document.createElement("div");
                url.textContent = item.url || "Unknown URL";
                url.style.cssText =
                    "font-weight:600;overflow-wrap:anywhere";

                const date = document.createElement("small");
                date.textContent = item.createdAt
                    ? new Date(item.createdAt).toLocaleString()
                    : "Date unavailable";
                date.style.color = "#9ca3af";

                left.append(url, date);

                const right = document.createElement("div");
                right.style.cssText =
                    "text-align:right;overflow-wrap:anywhere";

                const verdict = document.createElement("div");

                verdict.textContent =
                    `${item.verdict || "No verdict"} · ` +
                    `${item.riskScore === "" ? "score N/A" : `${item.riskScore}/100`}`;

                verdict.style.fontWeight = "700";

                const evidence = document.createElement("small");

                evidence.textContent =
                    `Redirect: ${item.redirectStatus || "NOT_RUN"}; ` +
                    `Sandbox: ${item.sandboxStatus || "NOT_RUN"}`;

                evidence.style.color = "#9ca3af";

                right.append(verdict, evidence);
                row.append(left, right);

                container.appendChild(row);
            }
        }

        byId("unified-report-export").addEventListener(
            "click",
            exportHistory
        );

        form.addEventListener("submit", async (event) => {
            event.preventDefault();

            let inputUrl;

            try {
                inputUrl = normalizeInput(urlInput.value);
            } catch (error) {
                status.textContent =
                    error.message || "The URL is invalid.";
                return;
            }

            submit.disabled = true;
            submit.textContent = "Generating report...";
            status.textContent =
                "Checking the local threat-intelligence engine...";

            results.hidden = true;

            byId("unified-report-screenshot-wrap").hidden = true;
            byId("unified-report-screenshot").removeAttribute("src");

            const report = {
                inputUrl,
                primaryThreat: null,
                destination: "",
                destinationThreat: null,
                redirect: {
                    status: "NOT_RUN",
                    error: "Redirect resolution was not requested.",
                    data: null
                },
                sandbox: {
                    status: "NOT_RUN",
                    error: "Browser sandbox analysis was not requested.",
                    data: null
                }
            };

            try {
                report.primaryThreat = await postJson(
                    "/api/v1/intelligence/lookup",
                    { url: inputUrl }
                );
            } catch (error) {
                status.textContent =
                    `Threat-intelligence lookup failed: ${error.message}`;

                submit.disabled = false;
                submit.textContent = "Generate Unified Report";
                return;
            }

            let inspectionUrl = inputUrl;

            // Optional short-link analysis.
            if (byId("unified-report-redirect").checked) {
                status.textContent =
                    "Checking threat intelligence; attempting short-link resolution...";

                try {
                    report.redirect.data = await postJson(
                        "/api/v1/redirect-analysis",
                        { url: inputUrl }
                    );

                    report.redirect.status =
                        report.redirect.data.status || "COMPLETED";

                    const destination =
                        report.redirect.data.destination ||
                        report.redirect.data.finalUrl;

                    if (
                        typeof destination === "string" &&
                        destination.trim()
                    ) {
                        try {
                            inspectionUrl = normalizeInput(destination);
                            report.destination = inspectionUrl;

                            // Check the resolved destination separately.
                            if (inspectionUrl !== inputUrl) {
                                status.textContent =
                                    "Checking the resolved destination against local threat intelligence...";

                                try {
                                    report.destinationThreat = await postJson(
                                        "/api/v1/intelligence/lookup",
                                        { url: inspectionUrl }
                                    );
                                } catch (error) {
                                    report.destinationThreat = {
                                        requestError: error.message
                                    };
                                }
                            }
                        } catch (error) {
                            report.redirect.destinationWarning =
                                "The returned destination was not accepted for further analysis: " +
                                error.message;
                        }
                    }
                } catch (error) {
                    report.redirect.status = "NOT_COMPLETED";
                    report.redirect.error = error.message;
                }
            }

            // Optional isolated browser inspection.
            if (byId("unified-report-sandbox").checked) {
                let parsed;

                try {
                    parsed = new URL(inspectionUrl);
                } catch {
                    parsed = null;
                }

                if (
                    !parsed ||
                    parsed.protocol !== "https:" ||
                    (parsed.port && parsed.port !== "443")
                ) {
                    report.sandbox.status = "SKIPPED";
                    report.sandbox.error =
                        "Sandbox skipped: it accepts valid HTTPS URLs on the standard port only.";
                } else {
                    status.textContent =
                        "Running the isolated browser sandbox. Do not enter credentials or private information into inspected pages.";

                    try {
                        report.sandbox.data = await postJson(
                            "/api/v1/sandbox-analysis",
                            { url: inspectionUrl }
                        );

                        report.sandbox.status =
                            report.sandbox.data.status || "COMPLETED";
                    } catch (error) {
                        report.sandbox.status = "NOT_COMPLETED";
                        report.sandbox.error = error.message;
                    }
                }
            }

            // Threat intelligence summary.
            renderCards("unified-report-threat-summary", [
                ["URL analysed", inputUrl],
                [
                    "Risk score (local engine)",
                    `${report.primaryThreat.riskScore}/100`
                ],
                ["Local verdict", report.primaryThreat.verdict],
                [
                    "Known local threat match",
                    report.primaryThreat.knownThreatMatch
                        ? "Yes"
                        : "No match found"
                ],
                ["Evidence level", report.primaryThreat.evidenceLevel],
                ["Hostname", report.primaryThreat.hostname],
                ["Registrable domain", report.primaryThreat.registrableDomain],
                ["Checked at", report.primaryThreat.checkedAt]
            ]);

            setText(
                "unified-report-threat-details",
                JSON.stringify(
                    {
                        matches: report.primaryThreat.matches || [],
                        explanations: report.primaryThreat.explanations || [],
                        resolvedDestinationLookup:
                            report.destinationThreat || null
                    },
                    null,
                    2
                )
            );

            // Redirect results.
            const redirectDisplay = report.redirect.data
                ? {
                    status: report.redirect.status,
                    originalUrl:
                        report.redirect.data.originalUrl || inputUrl,
                    destination:
                        report.destination ||
                        report.redirect.data.destination ||
                        report.redirect.data.finalUrl ||
                        null,
                    redirectChain:
                        report.redirect.data.redirectChain || [],
                    destinationLookup:
                        report.destinationThreat || null,
                    warning:
                        report.redirect.destinationWarning || null
                }
                : {
                    status: report.redirect.status,
                    error: report.redirect.error
                };

            setText(
                "unified-report-redirect-details",
                JSON.stringify(redirectDisplay, null, 2)
            );

            // Sandbox results.
            const sandbox = report.sandbox.data;

            renderCards(
                "unified-report-sandbox-summary",
                sandbox
                    ? [
                        ["Sandbox status", report.sandbox.status],
                        ["Inspected URL", sandbox.originalUrl || inspectionUrl],
                        ["Final URL", sandbox.finalUrl],
                        ["Page title", sandbox.pageTitle],
                        ["HTTP response", sandbox.httpStatus],
                        [
                            "Requests observed",
                            sandbox.requestCountRecorded ??
                            sandbox.requests?.length ??
                            0
                        ],
                        [
                            "Navigation error",
                            sandbox.navigationError || "None reported"
                        ]
                    ]
                    : [
                        ["Sandbox status", report.sandbox.status],
                        ["Details", report.sandbox.error]
                    ]
            );

            setText(
                "unified-report-sandbox-limitations",
                sandbox
                    ? `Limitations: ${
                        Array.isArray(sandbox.limitations)
                            ? sandbox.limitations.join(" ")
                            : "Browser observations do not prove the URL is safe."
                    }`
                    : "Browser observations were not collected for this report."
            );

            setText(
                "unified-report-sandbox-details",
                sandbox
                    ? JSON.stringify(
                        {
                            redirectChain: sandbox.redirectChain || [],
                            requests: sandbox.requests || [],
                            responses: sandbox.responses || [],
                            pageErrors: sandbox.pageErrors || [],
                            navigationError: sandbox.navigationError || null
                        },
                        null,
                        2
                    )
                    : report.sandbox.error
            );

            setText(
                "unified-report-sandbox-text",
                sandbox?.visibleTextSample ||
                "No visible page text was collected."
            );

            if (
                sandbox &&
                typeof sandbox.screenshotBase64 === "string" &&
                sandbox.screenshotBase64.length > 0
            ) {
                byId("unified-report-screenshot").src =
                    `data:image/jpeg;base64,${sandbox.screenshotBase64}`;

                byId("unified-report-screenshot-wrap").hidden = false;
            }

            saveSummary(report);
            renderHistory();

            results.hidden = false;

            status.textContent =
                "Report assembled. The local risk score and browser/redirect evidence are displayed separately.";

            submit.disabled = false;
            submit.textContent = "Generate Unified Report";
        });

        renderHistory();
    }

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            install,
            { once: true }
        );
    } else {
        install();
    }
})();