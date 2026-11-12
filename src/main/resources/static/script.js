const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

function readHistory() {
  try {
    const value = JSON.parse(localStorage.getItem("qrScanHistory") || "[]");
    return Array.isArray(value) ? value.slice(0, 10) : [];
  } catch {
    return [];
  }
}

const state = {
  mode: "url",
  history: readHistory(),
  testedUrl: null,
  testedLevel: null,
  requestInProgress: false,
  cameraStream: null,
  cameraAnimationId: null,
  cameraScanning: false,
  redirectContext: null,
  redirectRequestInProgress: false
};

window.addEventListener("load", () => {
  const boot = $("#bootScreen");
  if (boot) setTimeout(() => boot.classList.add("hide"), 1100);

  renderHistory();
  setupHistoryExport();
  setupRedirectAnalysis();
  setupReveal();
  setupTilt();
  setupSpace();
  setupCursorGlow();
});

function setupCursorGlow() {
  document.addEventListener("mousemove", (event) => {
    const glow = $(".cursor-glow");
    if (!glow) return;
    glow.style.left = event.clientX + "px";
    glow.style.top = event.clientY + "px";
  });
}

/* ===== REDIRECT ANALYSIS FEATURE ===== */

function setupRedirectAnalysis() {
  const analyzeButton = $("#analyzeBtn");
  const analysisDetails = $("#analysisDetails");

  if (!analyzeButton || !analysisDetails || $("#resolveShortUrlBtn")) {
    return;
  }

  // Create the button without changing index.html or style.css.
  const resolveButton = document.createElement("button");

  resolveButton.id = "resolveShortUrlBtn";
  resolveButton.type = "button";
  resolveButton.className = "cyber-button analyze";
  resolveButton.textContent = "RESOLVE SHORT URL ↗";
  resolveButton.title =
      "Inspect redirects for an approved HTTPS URL shortener";

  resolveButton.style.marginTop = "10px";
  resolveButton.style.width = "100%";

  analyzeButton.insertAdjacentElement("afterend", resolveButton);

  const hint = document.createElement("p");

  hint.textContent =
      "OPTIONAL: Reveal a shortened link's redirect path. The destination will not be opened.";

  hint.style.cssText =
      "font-size:9px;line-height:1.6;color:var(--muted);margin:7px 0 0;";

  resolveButton.insertAdjacentElement("afterend", hint);

  // Create the results panel.
  const resultPanel = document.createElement("div");

  resultPanel.id = "redirectAnalysisResult";
  resultPanel.hidden = true;

  resultPanel.style.cssText =
      "margin-top:14px;padding:14px;border:1px solid rgba(0,255,179,.25);" +
      "background:rgba(0,20,16,.62);border-radius:8px;overflow-wrap:anywhere;";

  // Place the redirect results OUTSIDE the clipped dashboard cards.
  const dashboardGrid = document.querySelector(".dashboard-grid");

  if (dashboardGrid) {
    dashboardGrid.insertAdjacentElement("afterend", resultPanel);

    resultPanel.style.width = "100%";
    resultPanel.style.boxSizing = "border-box";
    resultPanel.style.marginTop = "14px";
  } else {
    // Fallback if the dashboard grid is unavailable.
    analysisDetails.insertAdjacentElement("afterend", resultPanel);
  }

  resolveButton.addEventListener("click", resolveShortUrl);

  $("#targetUrl")?.addEventListener("input", clearRedirectAnalysis);
}

async function resolveShortUrl() {
  if (state.redirectRequestInProgress) return;

  const input = $("#targetUrl")?.value.trim();

  if (!input) {
    renderRedirectError(
        "Enter a URL first. Only approved HTTPS URL-shortener hosts are eligible."
    );
    return;
  }

  let url;

  try {
    url = normalizeUrl(input);
  } catch {
    renderRedirectError("Enter a valid HTTP or HTTPS URL.");
    return;
  }

  const button = $("#resolveShortUrlBtn");

  state.redirectRequestInProgress = true;

  if (button) {
    button.disabled = true;
    button.textContent = "RESOLVING REDIRECTS...";
  }

  renderRedirectLoading();

  try {
    const response = await fetch("/api/v1/redirect-analysis", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        url: url.href
      })
    });

    const data = await response.json().catch(() => null);

    if (!response.ok) {
      const detail =
          data?.error ||
          data?.detail ||
          data?.message ||
          data?.title;

      throw new Error(
          detail || `Redirect API returned HTTP ${response.status}.`
      );
    }

    if (
        !data ||
        typeof data !== "object" ||
        typeof data.status !== "string"
    ) {
      throw new Error(
          "The redirect API returned an unexpected response format."
      );
    }

    renderRedirectResult(data);

  } catch (error) {
    renderRedirectError(
        error instanceof TypeError
            ? "Could not reach Spring Boot. Make sure the application is running and this page is served from the same origin as the API."
            : (error.message || "Redirect analysis could not be completed.")
    );

  } finally {
    state.redirectRequestInProgress = false;

    if (button) {
      button.disabled = false;
      button.textContent = "RESOLVE SHORT URL ↗";
    }
  }
}

function renderRedirectLoading() {
  const panel = $("#redirectAnalysisResult");

  if (!panel) return;

  panel.hidden = false;

  panel.innerHTML = `
    <div style="font-size:10px;letter-spacing:1px;color:var(--line)">
      &gt; REDIRECT ANALYSIS
    </div>

    <p style="font-size:11px;color:var(--muted);margin:10px 0 0">
      Contacting the approved shortener to inspect its redirect response.
      The destination will not be opened.
    </p>
  `;
}

function renderRedirectResult(data) {
  const panel = $("#redirectAnalysisResult");
  if (!panel) return;

  const status = String(data.status || "UNKNOWN");
  const chain = Array.isArray(data.redirectChain)
      ? data.redirectChain
      : [];

  const destination = data.destination
      ? String(data.destination)
      : "";

  const requests = Number(data.requestsMade);
  const requestsText = Number.isFinite(requests)
      ? String(requests)
      : "Not provided";

  const message = data.message
      ? String(data.message)
      : "No additional details provided.";

  const statusColor = status === "DESTINATION_REVEALED"
      ? "var(--safe)"
      : status === "NO_REDIRECT_FOUND"
          ? "var(--warn)"
          : "var(--danger)";

  // Only offer the next action for a valid revealed HTTP(S) destination.
  let analyzableDestination = null;

  if (status === "DESTINATION_REVEALED" && destination) {
    try {
      analyzableDestination = normalizeUrl(destination).href;
    } catch {
      analyzableDestination = null;
    }
  }

  // Keep redirect information until the destination is analyzed.
  state.redirectContext = analyzableDestination
      ? {
        originalUrl: String(data.originalUrl || ""),
        redirectChain: chain.map((item) => String(item)),
        destination: analyzableDestination
      }
      : null;

  const chainHtml = chain.length
      ? chain.map((item, index) => `
        <div style="
          display:grid;
          grid-template-columns:22px minmax(0,1fr);
          gap:7px;
          padding:7px 0;
          border-bottom:1px solid rgba(0,255,179,.09);
          font-size:10px;
          line-height:1.6">

          <span style="color:var(--line)">${index + 1}.</span>

          <span style="color:var(--muted);overflow-wrap:anywhere">
            ${escapeHtml(item)}
          </span>
        </div>
      `).join("")
      : `
        <div style="font-size:10px;color:var(--muted);padding:7px 0">
          No redirect hops were returned.
        </div>
      `;

  const analyzeButtonHtml = analyzableDestination
      ? `
        <button
          id="analyzeResolvedDestinationBtn"
          type="button"
          class="cyber-button analyze"
          style="width:100%;margin-top:14px">

          ANALYZE REVEALED DESTINATION ↗
        </button>

        <p style="
          font-size:9px;
          line-height:1.6;
          color:var(--muted);
          margin:7px 0 0">

          Sends the revealed URL to the threat-analysis API.
          The website will not be opened.
        </p>
      `
      : "";

  panel.hidden = false;

  panel.innerHTML = `
    <div style="
      display:flex;
      flex-wrap:wrap;
      justify-content:space-between;
      align-items:center;
      gap:8px">

      <span style="font-size:10px;letter-spacing:1px;color:var(--line)">
        &gt; REDIRECT ANALYSIS
      </span>

      <strong style="font-size:10px;color:${statusColor}">
        ${escapeHtml(status)}
      </strong>
    </div>

    <div style="margin-top:12px">
      <div style="font-size:9px;color:var(--line);margin-bottom:5px">
        ORIGINAL URL
      </div>

      <div style="font-size:10px;color:var(--muted);overflow-wrap:anywhere">
        ${escapeHtml(data.originalUrl || "Not provided")}
      </div>
    </div>

    <div style="margin-top:12px">
      <div style="font-size:9px;color:var(--line);margin-bottom:5px">
        REDIRECT CHAIN
      </div>

      ${chainHtml}
    </div>

    <div style="
      margin-top:12px;
      padding:10px;
      border:1px solid rgba(0,255,179,.15);
      border-radius:5px">

      <div style="font-size:9px;color:var(--line);margin-bottom:5px">
        DESTINATION
      </div>

      <div style="
        font-size:11px;
        font-weight:600;
        color:var(--safe);
        overflow-wrap:anywhere">

        ${escapeHtml(destination || "Not identified")}
      </div>
    </div>

    <div style="font-size:9px;color:var(--muted);margin-top:10px">
      HTTP requests made: ${escapeHtml(requestsText)}
    </div>

    <p style="
      font-size:10px;
      line-height:1.6;
      color:var(--muted);
      margin:10px 0 0">

      ${escapeHtml(message)}
    </p>

    ${analyzeButtonHtml}

    <p style="
      font-size:9px;
      line-height:1.6;
      color:var(--muted);
      margin:10px 0 0">

      A revealed destination is not necessarily safe.
      A preliminary analysis cannot guarantee that a website is legitimate.
    </p>
  `;

  // Register the button only after the result panel has been rendered.
  const analyzeDestinationButton =
      $("#analyzeResolvedDestinationBtn");

  analyzeDestinationButton?.addEventListener("click", () => {
    if (!analyzableDestination || state.requestInProgress) return;

    // Switch to the URL input tab.
    state.mode = "url";

    $$(".tab").forEach((tab) => {
      tab.classList.toggle("active", tab.dataset.mode === "url");
    });

    $("#urlInputArea")?.classList.remove("hidden");
    $("#qrInputArea")?.classList.add("hidden");

    // Display the revealed destination in the input field.
    $("#targetUrl").value = analyzableDestination;

    // Run the existing backend threat assessment.
    analyze(analyzableDestination, false, true);
  });
}

function renderRedirectError(message) {
  const panel = $("#redirectAnalysisResult");

  if (!panel) return;

  panel.hidden = false;

  panel.innerHTML = `
    <div style="font-size:10px;letter-spacing:1px;color:var(--danger)">
      &gt; REDIRECT ANALYSIS UNAVAILABLE
    </div>

    <p style="font-size:10px;line-height:1.6;color:var(--muted);margin:10px 0 0">
      ${escapeHtml(message)}
    </p>

    <p style="font-size:9px;line-height:1.6;color:var(--muted);margin:8px 0 0">
      Only eligible HTTPS shortener URLs configured by the backend can be resolved.
    </p>
  `;
}

function clearRedirectAnalysis() {
  state.redirectContext = null;
  const panel = $("#redirectAnalysisResult");

  if (panel) {
    panel.hidden = true;
    panel.textContent = "";
  }
}

/* ===== END REDIRECT ANALYSIS FEATURE ===== */

/* Keep the original URL / QR image tabs and the original layout. */
$$(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    $$(".tab").forEach((tab) => tab.classList.remove("active"));
    button.classList.add("active");
    state.mode = button.dataset.mode;
    if (state.mode !== "qr") stopCamera();

    $("#urlInputArea")?.classList.toggle("hidden", state.mode !== "url");
    $("#qrInputArea")?.classList.toggle("hidden", state.mode !== "qr");
    clearWaitingError();
  });
});

$$(".quick-examples button").forEach((button) => {
  button.addEventListener("click", () => {
    state.mode = "url";
    $$(".tab").forEach((tab) => {
      tab.classList.toggle("active", tab.dataset.mode === "url");
    });

    $("#urlInputArea")?.classList.remove("hidden");
    $("#qrInputArea")?.classList.add("hidden");
    $("#targetUrl").value = button.dataset.url || "";
    analyze(button.dataset.url || "");
  });
});

$("#qrFile")?.addEventListener("change", (event) => {
  const file = event.target.files?.[0] || null;
  if (file) stopCamera();
  $("#fileName").textContent = file ? file.name : "No image selected";
});

const dropzone = $("#dropzone");
if (dropzone) {
  ["dragenter", "dragover"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.style.background = "rgba(0,255,179,.09)";
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.style.background = "";
    });
  });

  dropzone.addEventListener("drop", (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (!file) return;

    const input = $("#qrFile");
    try {
      const transfer = new DataTransfer();
      transfer.items.add(file);
      input.files = transfer.files;
      $("#fileName").textContent = file.name;
      state.mode = "qr";
      $$(".tab").forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.mode === "qr");
      });
      $("#urlInputArea")?.classList.add("hidden");
      $("#qrInputArea")?.classList.remove("hidden");
    } catch {
      showWaiting(
        "FILE SELECTION ERROR",
        "Use the upload control to select this image."
      );
    }
  });
}

const cameraVideo = $("#cameraVideo");
const cameraPanel = $("#cameraPanel");
const cameraStatus = $("#cameraStatus");
const startCameraButton = $("#startCameraBtn");
const stopCameraButton = $("#stopCameraBtn");
const liveScanCanvas = document.createElement("canvas");
const liveScanContext = liveScanCanvas.getContext("2d", { willReadFrequently: true });

startCameraButton?.addEventListener("click", startCamera);
stopCameraButton?.addEventListener("click", () => {
  stopCamera();
  showWaiting("CAMERA STOPPED", "Live QR scanning was stopped. You can restart the camera or upload a QR image.");
});
window.addEventListener("pagehide", () => stopCamera());

async function startCamera() {
  clearWaitingError();

  if (!navigator.mediaDevices?.getUserMedia) {
    showWaiting("CAMERA UNAVAILABLE", "This browser does not expose camera access. Open the app on localhost or HTTPS, or upload a QR image instead.");
    return;
  }

  if (!window.jsQR) {
    showWaiting("QR DECODER UNAVAILABLE", "The QR decoding library did not load. Reload the page or use QR image upload.");
    return;
  }

  stopCamera();
  if (cameraPanel) cameraPanel.classList.remove("hidden");
  if (cameraStatus) cameraStatus.textContent = "Requesting camera permission...";
  if (startCameraButton) startCameraButton.disabled = true;

  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: {
        facingMode: { ideal: "environment" },
        width: { ideal: 1280 },
        height: { ideal: 720 }
      }
    });

    state.cameraStream = stream;
    cameraVideo.srcObject = stream;
    await cameraVideo.play();
    state.cameraScanning = true;
    if (startCameraButton) startCameraButton.disabled = true;
    if (stopCameraButton) stopCameraButton.disabled = false;
    if (cameraStatus) cameraStatus.textContent = "Camera active. Hold the QR code inside the frame.";
    scanCameraFrame();
  } catch (error) {
    stopCamera();
    showWaiting(
      "CAMERA ACCESS FAILED",
      error?.name === "NotAllowedError"
        ? "Camera permission was denied. Allow camera access in your browser settings, or upload a QR image instead."
        : "The camera could not start. Make sure no other app is using it, then try again or upload an image."
    );
  }
}

function stopCamera() {
  state.cameraScanning = false;
  if (state.cameraAnimationId !== null) {
    cancelAnimationFrame(state.cameraAnimationId);
    state.cameraAnimationId = null;
  }

  if (state.cameraStream) {
    state.cameraStream.getTracks().forEach((track) => track.stop());
    state.cameraStream = null;
  }

  if (cameraVideo) cameraVideo.srcObject = null;
  if (cameraPanel) cameraPanel.classList.add("hidden");
  if (startCameraButton) startCameraButton.disabled = false;
  if (stopCameraButton) stopCameraButton.disabled = true;
}

function scanCameraFrame() {
  if (!state.cameraScanning || !cameraVideo || !liveScanContext) return;

  if (cameraVideo.readyState >= HTMLMediaElement.HAVE_ENOUGH_DATA &&
      cameraVideo.videoWidth > 0 && cameraVideo.videoHeight > 0) {
    const maxDimension = 1000;
    const scale = Math.min(
      1,
      maxDimension / Math.max(cameraVideo.videoWidth, cameraVideo.videoHeight)
    );
    const width = Math.max(1, Math.floor(cameraVideo.videoWidth * scale));
    const height = Math.max(1, Math.floor(cameraVideo.videoHeight * scale));

    if (liveScanCanvas.width !== width || liveScanCanvas.height !== height) {
      liveScanCanvas.width = width;
      liveScanCanvas.height = height;
    }

    liveScanContext.drawImage(cameraVideo, 0, 0, width, height);
    const frame = liveScanContext.getImageData(0, 0, width, height);
    const code = window.jsQR(
      frame.data,
      frame.width,
      frame.height,
      { inversionAttempts: "attemptBoth" }
    );

    if (code?.data) {
      const decodedPayload = code.data;
      stopCamera();

      // Show the decoded payload first. The user must review and click ANALYZE TARGET.
      state.mode = "url";
      $$(".tab").forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.mode === "url");
      });
      $("#urlInputArea")?.classList.remove("hidden");
      $("#qrInputArea")?.classList.add("hidden");
      $("#targetUrl").value = decodedPayload;
      showWaiting(
        "QR DECODED — REVIEW DESTINATION",
        "The QR payload was decoded locally. Review the URL shown in TARGET URL, then click ANALYZE TARGET. The destination has not been opened."
      );
      $("#targetUrl")?.focus();
      return;
    }
  }

  if (state.cameraScanning) {
    state.cameraAnimationId = requestAnimationFrame(scanCameraFrame);
  }
}

$("#openUrlBtn")?.addEventListener("click", () => {
  if (!state.testedUrl) return;

  const risky = ["KNOWN THREAT", "HIGH RISK", "CAUTION"].includes(
    state.testedLevel
  );

  if (risky) {
    const proceed = confirm(
      "WARNING: This URL was flagged as " + state.testedLevel +
      ". Opening it may expose you to phishing or other unsafe content.\n\n" +
      "Open the tested URL anyway?"
    );
    if (!proceed) return;
  } else {
    const proceed = confirm(
      "A low risk score or no known threat match is not proof of safety.\n\n" +
      "Open this URL anyway?"
    );
    if (!proceed) return;
  }

  window.open(state.testedUrl, "_blank", "noopener,noreferrer");
});

$("#analyzeBtn")?.addEventListener("click", async () => {
  if (state.requestInProgress) return;

  if (state.mode === "url") {
    const value = $("#targetUrl").value.trim();
    if (!value) {
      showWaiting("INPUT REQUIRED", "Enter a URL before starting analysis.");
      return;
    }
    await analyze(value);
  } else {
    const file = $("#qrFile").files?.[0];
    if (!file) {
      showWaiting("IMAGE REQUIRED", "Upload a QR image before starting analysis.");
      return;
    }
    await decodeQR(file);
  }
});

async function decodeQR(file) {
  if (!file.type || !["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
    showWaiting("UNSUPPORTED IMAGE", "Choose a PNG, JPG, or WEBP image.");
    return;
  }

  if (file.size > 5 * 1024 * 1024) {
    showWaiting("IMAGE TOO LARGE", "Choose an image smaller than 5 MB.");
    return;
  }

  showWaiting("DECODING", "Reading QR payload locally. No destination is opened.");

  let bitmap;
  try {
    if (!window.jsQR) {
      showWaiting(
        "QR DECODER UNAVAILABLE",
        "The QR decoding library did not load. Check your connection and reload the page."
      );
      return;
    }

    bitmap = await createImageBitmap(file);
    const canvas = document.createElement("canvas");
    const maxDimension = 1400;
    const scale = Math.min(
      1,
      maxDimension / Math.max(bitmap.width, bitmap.height)
    );

    canvas.width = Math.max(1, Math.floor(bitmap.width * scale));
    canvas.height = Math.max(1, Math.floor(bitmap.height * scale));

    const context = canvas.getContext("2d", { willReadFrequently: true });
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);

    const image = context.getImageData(0, 0, canvas.width, canvas.height);
    const code = window.jsQR(
      image.data,
      image.width,
      image.height,
      { inversionAttempts: "attemptBoth" }
    );

    if (!code?.data) {
      showWaiting(
        "QR NOT DETECTED",
        "No readable QR payload was found. Try a clearer, well-lit image."
      );
      return;
    }

    $("#targetUrl").value = code.data;
    state.mode = "url";
    $$(".tab").forEach((tab) => {
      tab.classList.toggle("active", tab.dataset.mode === "url");
    });
    $("#urlInputArea")?.classList.remove("hidden");
    $("#qrInputArea")?.classList.add("hidden");

    // Analyse the decoded payload with the same backend engine as typed URLs.
    await analyze(code.data, true);
  } catch (error) {
    showWaiting(
      "DECODE ERROR",
      "The image could not be processed. Try a different PNG, JPG, or WEBP image."
    );
  } finally {
    if (bitmap && typeof bitmap.close === "function") bitmap.close();
  }
}

function normalizeUrl(raw) {
  let value = String(raw || "").trim();
  if (!/^https?:\/\//i.test(value)) {
    value = "https://" + value;
  }

  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs can be analysed.");
  }
  return url;
}

async function analyze(
    raw,
    fromQR = false,
    preserveRedirect = false
) {
  if (state.requestInProgress) return;

  let url;
  try {
    url = normalizeUrl(raw);
  } catch {
    showWaiting("INVALID URL", "The supplied target is not a valid HTTP or HTTPS web address.");
    return;
  }
  if (!preserveRedirect) {
    clearRedirectAnalysis();
  }
  state.requestInProgress = true;
  const analyzeButton = $("#analyzeBtn");
  if (analyzeButton) analyzeButton.disabled = true;

  setStatus("ANALYZING", "Sending the URL to the local Spring Boot detection engine...");
  $("#riskScore").textContent = "—/100";
  $("#riskBar").style.width = "0%";
  $("#analysisDetails").textContent = "Checking local threat indicators and URL structure...";
  state.testedUrl = null;
  state.testedLevel = null;
  $("#openUrlBtn").disabled = true;

  try {
    const response = await fetch("/api/v1/intelligence/lookup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({ url: url.href })
    });

    const data = await response.json().catch(() => null);

    if (!response.ok) {
      const detail = data?.detail || data?.message || data?.title;
      throw new Error(
        detail || `Detection API returned HTTP ${response.status}.`
      );
    }

    if (
      !data ||
      typeof data !== "object" ||
      !Number.isFinite(Number(data.riskScore)) ||
      typeof data.verdict !== "string"
    ) {
      throw new Error("The detection API returned an unexpected response format.");
    }

    const result = mapBackendResult(url, data, fromQR);
    renderResult(url, result, fromQR);
    saveHistory(url.href, result);
  } catch (error) {
    showWaiting(
      "BACKEND UNAVAILABLE",
      error instanceof TypeError
        ? "Could not reach the Spring Boot API. Make sure the application is running at localhost:8080."
        : (error.message || "The scan could not be completed.")
    );
  } finally {
    state.requestInProgress = false;
    if (analyzeButton) analyzeButton.disabled = false;
  }
}

function mapBackendResult(url, data, fromQR) {
  const score = Math.max(0, Math.min(100, Math.round(Number(data.riskScore))));
  const verdict = data.verdict;

  let level;
  let cssClass;
  let icon;
  let description;

  if (data.knownThreatMatch || verdict === "KNOWN_THREAT_MATCH") {
    level = "KNOWN THREAT";
    cssClass = "danger";
    icon = "×";
    description = "An active threat indicator matched in the local database. Avoid visiting this destination.";
  } else if (verdict === "HIGH_RISK") {
    level = "HIGH RISK";
    cssClass = "danger";
    icon = "×";
    description = "Multiple warning signals were found. Investigate before proceeding.";
  } else if (verdict === "SUSPICIOUS") {
    level = "CAUTION";
    cssClass = "warning";
    icon = "!";
    description = "The URL has structural warning signals that warrant caution.";
  } else {
    level = "NO KNOWN THREAT";
    cssClass = "safe";
    icon = "✓";
    description = "No known threat was identified by the current checks. This is not proof that the URL is safe.";
  }

  return {
    score,
    level,
    cssClass,
    icon,
    description,
    verdict,
    evidenceLevel: data.evidenceLevel || "NOT PROVIDED",
    knownThreatMatch: Boolean(data.knownThreatMatch),
    host: data.hostname || url.hostname,
    registrableDomain: data.registrableDomain || "",
    protocol: url.protocol.replace(":", ""),
    length: url.href.length,
    explanations: Array.isArray(data.explanations) ? data.explanations : [],
    matches: Array.isArray(data.matches) ? data.matches : [],
    checkedAt: data.checkedAt || null,
    fromQR
  };
}

function renderResult(url, result, fromQR) {
  state.testedUrl = url.href;
  state.testedLevel = result.level;

  const openButton = $("#openUrlBtn");
  const openNote = $("#openUrlNote");
  openButton.disabled = false;

  if (result.cssClass === "danger") {
    openNote.textContent = "⚠ High-risk target. Opening requires confirmation.";
    openNote.className = "open-url-note danger";
  } else if (result.cssClass === "warning") {
    openNote.textContent = "⚠ Caution target. Review the signals before opening.";
    openNote.className = "open-url-note warning";
  } else {
    openNote.textContent = "No known threat matched. This does not establish safety; opening still requires confirmation.";
    openNote.className = "open-url-note";
  }

  setStatus(
    result.level,
    result.knownThreatMatch
      ? "A current local threat indicator matched this URL."
      : "The backend returned a preliminary assessment. Review the evidence below."
  );

  $("#riskScore").textContent = `${result.score}/100`;
  $("#riskBar").style.width = result.score + "%";

  const color = result.cssClass === "danger"
    ? "var(--danger)"
    : result.cssClass === "warning"
      ? "var(--warn)"
      : "var(--safe)";

  $("#riskBar").style.background = color;
  $("#riskBar").style.boxShadow = `0 0 18px ${color}`;

  const verdictBox = $("#verdictBox");
  verdictBox.className = "verdict " + result.cssClass;
  verdictBox.querySelector(".verdict-icon").textContent = result.icon;
  verdictBox.querySelector("b").textContent = result.level;
  verdictBox.querySelector("small").textContent = result.description;

  const explanationLines = result.explanations.length
    ? result.explanations
    : ["The backend did not return detailed explanations."];

  const detailsHtml = `
    <div class="detail-grid">
      <div class="detail-item"><small>HOST</small><b>${escapeHtml(result.host)}</b></div>
      <div class="detail-item"><small>REGISTRABLE DOMAIN</small><b>${escapeHtml(result.registrableDomain || "Not available")}</b></div>
      <div class="detail-item"><small>PROTOCOL</small><b>${escapeHtml(result.protocol.toUpperCase())}</b></div>
      <div class="detail-item"><small>URL LENGTH</small><b>${result.length} chars</b></div>
      <div class="detail-item"><small>INPUT</small><b>${fromQR ? "QR IMAGE" : "DIRECT URL"}</b></div>
      <div class="detail-item"><small>EVIDENCE LEVEL</small><b>${escapeHtml(result.evidenceLevel)}</b></div>
      <div class="detail-item"><small>BACKEND VERDICT</small><b>${escapeHtml(result.verdict)}</b></div>
      <div class="detail-item"><small>CHECKED AT</small><b>${escapeHtml(formatDate(result.checkedAt))}</b></div>
    </div>
    <div style="margin-top:12px">
      <div style="font-size:9px;color:var(--line);margin-bottom:7px">&gt; EXPLANATIONS</div>
      ${explanationLines.map(line =>
        `<div style="font-size:10px;color:var(--muted);padding:5px 0;border-bottom:1px solid rgba(0,255,179,.07)">• ${escapeHtml(line)}</div>`
      ).join("")}
    </div>
    <div style="font-size:8px;color:#477f70;margin-top:12px">
      Preliminary rule-based risk index — not a probability. No known threat match is not proof of safety.
    </div>
  `;

  $("#analysisDetails").innerHTML = detailsHtml;
}

function setStatus(status, message) {
  $("#statusText").textContent = status;
  $("#statusMessage").textContent = message;
}

function showWaiting(status, message) {
  setStatus(status, message);
  $("#riskScore").textContent = "0/100";
  $("#riskBar").style.width = "0%";
  $("#riskBar").style.background = "var(--safe)";
  state.testedUrl = null;
  state.testedLevel = null;
  $("#openUrlBtn").disabled = true;
  $("#openUrlNote").textContent = "The button becomes available after a successful scan.";
  $("#openUrlNote").className = "open-url-note";

  const verdictBox = $("#verdictBox");
  verdictBox.className = "verdict";
  verdictBox.querySelector(".verdict-icon").textContent = "◈";
  verdictBox.querySelector("b").textContent = status;
  verdictBox.querySelector("small").textContent = message;
  $("#analysisDetails").textContent = message;
}

function clearWaitingError() {
  const status = $("#statusText")?.textContent;
  if (status === "BACKEND UNAVAILABLE" || status === "INVALID URL" || status === "INPUT REQUIRED") {
    setStatus("WAITING", "Enter a URL or upload a QR image.");
  }
}

function saveHistory(url, result) {
  // Attach redirect evidence only when the analyzed URL
  // matches the destination from the saved redirect result.
  const context = state.redirectContext;

  const redirect =
      context && context.destination === url
          ? {
            originalUrl: context.originalUrl,
            redirectChain: [...context.redirectChain],
            destination: context.destination
          }
          : null;

  state.history.unshift({
    url,
    score: result.score,
    level: result.level,
    time: new Date().toLocaleString(),
    redirect
  });

  state.history = state.history.slice(0, 10);

  try {
    localStorage.setItem(
        "qrScanHistory",
        JSON.stringify(state.history)
    );
  } catch {
    // The scan can still complete if browser storage is unavailable.
  }

  renderHistory();
}

function renderHistory() {
  const element = $("#historyList");
  if (!element) return;

  if (!state.history.length) {
    element.innerHTML = `
      <div class="empty-history">
        <div>▤</div>
        <p>No previous scans</p>
        <small>Results will appear here.</small>
      </div>`;
    return;
  }

  element.innerHTML = state.history.map((item) => {
    const cls =
        item.score >= 50 || item.level === "KNOWN THREAT"
            ? "danger"
            : item.score >= 25 || item.level === "CAUTION"
                ? "warning"
                : "safe";

    const redirect = item.redirect;
    const chain = Array.isArray(redirect?.redirectChain)
        ? redirect.redirectChain
        : [];

    const redirectHtml = redirect
        ? `
        <div style="
          margin-top:9px;
          padding:9px;
          border:1px solid rgba(0,255,179,.16);
          background:rgba(0,255,179,.025);
          overflow-wrap:anywhere">

          <div style="
            font-size:8px;
            color:var(--line);
            margin-bottom:4px">
            REDIRECT CONTEXT
          </div>

          <div style="font-size:9px;color:var(--muted);margin-top:5px">
            ORIGINAL SHORT URL
          </div>

          <div style="font-size:10px;color:#b9ffea;overflow-wrap:anywhere">
            ${escapeHtml(redirect.originalUrl || "Not available")}
          </div>

          <div style="
            font-size:9px;
            color:var(--muted);
            margin-top:7px">
            REDIRECT CHAIN
          </div>

          ${
            chain.length
                ? chain.map((hop, index) => `
                  <div style="
                    font-size:9px;
                    line-height:1.6;
                    color:var(--muted);
                    overflow-wrap:anywhere;
                    margin-top:3px">

                    ${index + 1}. ${escapeHtml(hop)}
                  </div>
                `).join("")
                : `
                  <div style="font-size:9px;color:var(--muted)">
                    No redirect hops recorded.
                  </div>
                `
        }

          <div style="
            font-size:9px;
            color:var(--muted);
            margin-top:7px">
            ANALYZED DESTINATION
          </div>

          <div style="
            font-size:10px;
            color:var(--safe);
            overflow-wrap:anywhere">

            ${escapeHtml(redirect.destination || item.url)}
          </div>
        </div>
      `
        : "";

    return `
      <div class="history-item">

        <div class="h-top">
          <span>${escapeHtml(item.time)}</span>
          <b class="${cls}">${escapeHtml(item.level)}</b>
        </div>

        <div class="h-url">${escapeHtml(item.url)}</div>

        <div class="h-risk ${cls}">
          RISK ${Number(item.score)}/100
        </div>

        ${redirectHtml}

      </div>
    `;
  }).join("");
}

function formatDate(value) {
  if (!value) return "Not provided";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Not provided" : date.toLocaleString();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[character]);
}

function setupReveal() {
  if (!("IntersectionObserver" in window)) {
    $$(".reveal").forEach((element) => element.classList.add("visible"));
    return;
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) entry.target.classList.add("visible");
    });
  }, { threshold: 0.12 });

  $$(".reveal").forEach((element) => observer.observe(element));
}

function setupTilt() {
  $$(".tilt").forEach((card) => {
    card.addEventListener("mousemove", (event) => {
      if (innerWidth < 800) return;
      const rect = card.getBoundingClientRect();
      const x = ((event.clientX - rect.left) / rect.width - 0.5) * 8;
      const y = ((event.clientY - rect.top) / rect.height - 0.5) * -8;
      card.style.transform =
        `perspective(900px) rotateX(${y}deg) rotateY(${x}deg) translateY(-2px)`;
    });

    card.addEventListener("mouseleave", () => {
      card.style.transform = "";
    });
  });
}

function setupSpace() {
  const canvas = $("#spaceCanvas");
  if (!canvas) return;

  const context = canvas.getContext("2d");
  if (!context) return;

  let width;
  let height;
  let stars = [];

  function resize() {
    width = canvas.width = innerWidth;
    height = canvas.height = innerHeight;
    stars = Array.from({ length: 100 }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      z: Math.random() * 1.8 + 0.2,
      speed: Math.random() * 1.5 + 0.3
    }));
  }

  resize();
  addEventListener("resize", resize);

  function draw() {
    context.clearRect(0, 0, width, height);

    for (const star of stars) {
      star.y += star.speed * 0.25;
      if (star.y > height) star.y = 0;
      context.globalAlpha = 0.15 + star.z * 0.22;
      context.fillStyle = "#00ffb3";
      context.fillRect(star.x, star.y, star.z, star.z);
    }

    context.globalAlpha = 1;
    requestAnimationFrame(draw);
  }

  draw();
}

/* ===== EXPORT SCAN HISTORY ===== */

function setupHistoryExport() {
  const clearButton = $("#clearHistory");
  // CLEAR SCAN HISTORY
  // Attach the listener only once.
  if (clearButton && !clearButton.dataset.clearHandlerBound) {

    clearButton.addEventListener("click", () => {

      const confirmed = window.confirm(
          "Are you sure you want to clear all scan history? This action cannot be undone."
      );

      if (!confirmed) {
        return;
      }

      // Clear history from application state.
      state.history = [];

      // Remove saved history from browser storage.
      try {
        localStorage.removeItem("qrScanHistory");
      } catch (error) {
        console.error("Could not clear saved scan history:", error);
      }

      // Immediately refresh the existing history interface.
      renderHistory();

    });

    clearButton.dataset.clearHandlerBound = "true";
  }

  if (!clearButton || $("#exportHistoryBtn")) {
    return;
  }

  const exportButton = document.createElement("button");

  exportButton.id = "exportHistoryBtn";
  exportButton.type = "button";
  exportButton.textContent = "[ EXPORT ]";
  exportButton.title = "Download scan history as a CSV file";

  // Reuse the existing history-header button styling.
  exportButton.style.marginLeft = "6px";

  clearButton.insertAdjacentElement("beforebegin", exportButton);

  exportButton.addEventListener("click", exportScanHistory);
}

function exportScanHistory() {
  if (!Array.isArray(state.history) || state.history.length === 0) {
    alert("No scan history is available to export yet.");
    return;
  }

  const headers = [
    "Timestamp",
    "Analyzed URL",
    "Verdict",
    "Risk Score",
    "Original Short URL",
    "Redirect Chain",
    "Resolved Destination"
  ];

  // Prevent spreadsheet formula injection in exported cells.
  function safeCsvCell(value) {
    let text = String(value ?? "");

    if (/^[\s]*[=+\-@]/.test(text)) {
      text = "'" + text;
    }

    return '"' + text.replace(/"/g, '""') + '"';
  }

  const rows = state.history.map((item) => {
    const redirect = item.redirect || {};

    const chain = Array.isArray(redirect.redirectChain)
        ? redirect.redirectChain.join(" -> ")
        : "";

    return [
      item.time || "",
      item.url || "",
      item.level || "",
      Number.isFinite(Number(item.score))
          ? Number(item.score)
          : "",
      redirect.originalUrl || "",
      chain,
      redirect.destination || ""
    ];
  });

  const csv = [
    headers,
    ...rows
  ]
      .map((row) => row.map(safeCsvCell).join(","))
      .join("\r\n");

  // The BOM helps spreadsheet applications recognize UTF-8.
  const blob = new Blob(
      ["\uFEFF", csv],
      { type: "text/csv;charset=utf-8;" }
  );

  const objectUrl = URL.createObjectURL(blob);
  const downloadLink = document.createElement("a");

  const date = new Date().toISOString().slice(0, 10);

  downloadLink.href = objectUrl;
  downloadLink.download = `qr-phishing-scan-history-${date}.csv`;

  document.body.appendChild(downloadLink);
  downloadLink.click();
  downloadLink.remove();

  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

/* ===== END EXPORT SCAN HISTORY ===== */
