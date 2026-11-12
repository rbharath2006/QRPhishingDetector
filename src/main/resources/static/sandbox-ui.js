
(() => {
    "use strict";

    function installSandboxPanel() {
        if (document.getElementById("sandbox-analysis-panel")) {
            return;
        }

        const panel = document.createElement("section");
        panel.id = "sandbox-analysis-panel";

        panel.style.cssText = [
            "grid-column:1/-1",
            "width:100%",
            "box-sizing:border-box",
            "margin:20px 0",
            "padding:24px",
            "border:1px solid #374151",
            "border-radius:14px",
            "background:#111827",
            "color:#e5e7eb",
            "font-family:inherit"
        ].join(";");

        panel.innerHTML = `
            <h2 style="margin-top:0">Browser Sandbox Analysis</h2>

            <p>
                Inspect an HTTPS page in an isolated browser environment.
                The collected observations are evidence, not proof that a
                website is safe or malicious.
            </p>

            <form id="sandbox-analysis-form">
                <label for="sandbox-analysis-url">
                    HTTPS URL to inspect
                </label>

                <div style="
                    display:flex;
                    flex-wrap:wrap;
                    gap:12px;
                    margin-top:8px;
                ">
                    <input
                        id="sandbox-analysis-url"
                        name="url"
                        type="url"
                        maxlength="2048"
                        required
                        placeholder="https://example.com/"
                        value="https://example.com/"
                        style="
                            flex:1;
                            min-width:220px;
                            padding:12px;
                            border:1px solid #4b5563;
                            border-radius:8px;
                            background:#030712;
                            color:#f9fafb;
                        "
                    >

                    <button
                        id="sandbox-analysis-submit"
                        type="submit"
                        style="
                            padding:12px 18px;
                            border:0;
                            border-radius:8px;
                            background:#2563eb;
                            color:white;
                            font-weight:600;
                            cursor:pointer;
                        "
                    >
                        Analyze in Sandbox
                    </button>
                </div>
            </form>

            <p
                id="sandbox-analysis-status"
                role="status"
                aria-live="polite"
            >Ready for analysis.</p>

            <div id="sandbox-analysis-results" hidden>
                <h3>Browser observations</h3>

                <dl
                    id="sandbox-analysis-summary"
                    style="
                        display:grid;
                        grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
                        gap:12px;
                    "
                ></dl>

                <h3>Visible page text sample</h3>
                <pre
                    id="sandbox-analysis-text"
                    style="
                        max-height:240px;
                        overflow:auto;
                        white-space:pre-wrap;
                        overflow-wrap:anywhere;
                        padding:12px;
                        border-radius:8px;
                        background:#030712;
                    "
                ></pre>

                <div id="sandbox-screenshot-container" hidden>
                    <h3>Sandbox screenshot</h3>
                    <img
                        id="sandbox-analysis-screenshot"
                        alt="Screenshot captured by the isolated browser"
                        style="
                            display:block;
                            max-width:100%;
                            max-height:600px;
                            border:1px solid #374151;
                            border-radius:8px;
                        "
                    >
                </div>

                <details style="margin-top:16px">
                    <summary>Network and browser details</summary>
                    <pre
                        id="sandbox-analysis-observations"
                        style="
                            max-height:320px;
                            overflow:auto;
                            white-space:pre-wrap;
                            overflow-wrap:anywhere;
                        "
                    ></pre>
                </details>

                <p id="sandbox-analysis-limitations"></p>
            </div>
        `;

        const host =
            document.querySelector(".dashboard-grid") ||
            document.querySelector("main") ||
            document.body;

        host.appendChild(panel);

        const form = panel.querySelector("#sandbox-analysis-form");
        const input = panel.querySelector("#sandbox-analysis-url");
        const button = panel.querySelector("#sandbox-analysis-submit");
        const status = panel.querySelector("#sandbox-analysis-status");
        const results = panel.querySelector("#sandbox-analysis-results");
        const summary = panel.querySelector("#sandbox-analysis-summary");
        const textSample = panel.querySelector("#sandbox-analysis-text");
        const observations =
            panel.querySelector("#sandbox-analysis-observations");
        const limitations =
            panel.querySelector("#sandbox-analysis-limitations");
        const screenshotContainer =
            panel.querySelector("#sandbox-screenshot-container");
        const screenshot =
            panel.querySelector("#sandbox-analysis-screenshot");

        form.addEventListener("submit", async (event) => {
            event.preventDefault();

            const submittedUrl = input.value.trim();

            let parsedUrl;

            try {
                parsedUrl = new URL(submittedUrl);
            } catch {
                status.textContent = "Enter a valid URL.";
                return;
            }

            if (
                parsedUrl.protocol !== "https:" ||
                parsedUrl.username ||
                parsedUrl.password ||
                (parsedUrl.port && parsedUrl.port !== "443") ||
                submittedUrl.length > 2048
            ) {
                status.textContent =
                    "Only valid HTTPS URLs on the standard port are accepted.";
                return;
            }

            button.disabled = true;
            button.textContent = "Analyzing...";
            status.textContent =
                "Running isolated browser analysis. Please wait.";
            results.hidden = true;
            screenshotContainer.hidden = true;
            screenshot.removeAttribute("src");

            try {
                const response = await fetch(
                    "/api/v1/sandbox-analysis",
                    {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "Accept": "application/json"
                        },
                        body: JSON.stringify({ url: submittedUrl })
                    }
                );

                const data = await response.json().catch(() => ({}));

                if (!response.ok) {
                    status.textContent =
                        data.error ||
                        `Sandbox analysis failed (HTTP ${response.status}).`;
                    return;
                }

                const rows = [
                    ["Result", data.status],
                    ["Original URL", data.originalUrl],
                    ["Final URL", data.finalUrl],
                    ["Page title", data.pageTitle],
                    ["HTTP response", data.httpStatus],
                    [
                        "Requests observed",
                        data.requestCountRecorded ??
                        data.requests?.length ??
                        0
                    ],
                    ["Navigation error", data.navigationError || "None"]
                ];

                summary.replaceChildren();

                for (const [label, value] of rows) {
                    const term = document.createElement("dt");
                    term.textContent = label;
                    term.style.cssText =
                        "font-weight:700;color:#93c5fd;margin-bottom:4px";

                    const description = document.createElement("dd");
                    description.textContent =
                        value === null || value === undefined
                            ? "Not available"
                            : String(value);

                    description.style.cssText =
                        "margin:0;overflow-wrap:anywhere";

                    const item = document.createElement("div");
                    item.style.cssText =
                        "padding:12px;border:1px solid #374151;border-radius:8px";
                    item.append(term, description);
                    summary.appendChild(item);
                }

                textSample.textContent = (
                    data.visibleTextSample || "No visible text sample collected."
                ).slice(0, 2000);

                observations.textContent = JSON.stringify({
                    redirectChain: data.redirectChain || [],
                    requests: data.requests || [],
                    responses: data.responses || [],
                    pageErrors: data.pageErrors || []
                }, null, 2);

                limitations.textContent =
                    "Limitations: " +
                    (Array.isArray(data.limitations)
                        ? data.limitations.join(" ")
                        : "Browser observations do not prove a page is safe.");

                if (
                    typeof data.screenshotBase64 === "string" &&
                    data.screenshotBase64.length > 0
                ) {
                    screenshot.src =
                        "data:image/jpeg;base64," + data.screenshotBase64;
                    screenshotContainer.hidden = false;
                }

                results.hidden = false;
                status.textContent =
                    "Analysis completed. Review the observations; they are not a definitive safety verdict.";
            } catch {
                status.textContent =
                    "Could not reach the sandbox-analysis endpoint. " +
                    "Check that the Spring Boot application and sandbox are running.";
            } finally {
                button.disabled = false;
                button.textContent = "Analyze in Sandbox";
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", installSandboxPanel, {
            once: true
        });
    } else {
        installSandboxPanel();
    }
})();
