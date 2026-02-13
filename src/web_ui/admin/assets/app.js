async function load(endpoint) {
    const r = await fetch(endpoint);
    return r.json();
}

function el(id, html) {
    document.getElementById(id).innerHTML = html;
}

function setText(id, value) {
    const n = document.getElementById(id);
    if (n) n.textContent = value ?? "?";
}

async function refresh() {
    const [status, metrics, recent, suspicious] = await Promise.all([
        //FIXME - hard-coded
        load("/fantasma0/admin/api/status"),
        load("/fantasma0/admin/api/metrics"),
        load("/fantasma0/admin/api/recent"),
        load("/fantasma0/admin/api/suspicious"),
        //
    ]);

    el("m_mode", `${status.mode}`);
    el("m_uptime", `${Math.floor(status.uptime_seconds / 3600)}h`);

    setText("m_rps", metrics.rps);
    setText("m_blocked", metrics.blocked);
    setText("m_rate_limited", metrics.rate_limited);

    el(
        "recent",
        `
    <h2>Recent activity</h2>
    <table>
      ${recent
          .map(
              (r) =>
                  `<tr>
          <td class="mono">${r.ts}</td>
          <td class="mono">${r.ip}</td>
          <td>${r.decision}</td>
          <td>${r.reason || ""}</td>
        </tr>`,
          )
          .join("")}
    </table>
  `,
    );

    el(
        "suspicious",
        `
    <h2>Suspicious IPs</h2>
    <table>
      ${suspicious
          .map(
              (s) =>
                  `<tr>
          <td class="mono">${s.ip}</td>
          <td>${s.score}</td>
          <td>${s.last_seen}</td>
        </tr>`,
          )
          .join("")}
    </table>
  `,
    );
}

refresh();
setInterval(refresh, 15 * 1000);
