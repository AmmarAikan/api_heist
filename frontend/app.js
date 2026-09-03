(() => {
  const API = window.location.origin.includes("5500")
    ? "http://127.0.0.1:5000"
    : "";

  const STORAGE_KEY = "api-heist-academy-hardening-guide-v3";
  const TOKEN_KEY = "api-heist-academy-access-token";

  const state = {
    rulesAccepted: false,
    hardened: true,
    accessToken: sessionStorage.getItem(TOKEN_KEY),
    teamName: null,
    members: [],
    assignedChallenge: null,
    totalPoints: 0,
    challengesMeta: [],
    sessionChallenges: {},
    challengeStartedAt: null,
    session: {
      remainingSeconds: 100 * 60,
      running: false,
      ended: false,
      nextChallenge: 1,
    },
    pollId: null,
    pendingTeamName: null,
  };

  const $ = (sel) => document.querySelector(sel);
  const escapeHtml = (value) =>
    String(value ?? "").replace(
      /[&<>'"]/g,
      (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]
    );
  const views = {
    rules: $("#view-rules"),
    register: $("#view-register"),
    handoff: $("#view-handoff"),
    ended: $("#view-ended"),
    roadmap: $("#view-roadmap"),
    challenge: $("#view-challenge"),
    leaderboard: $("#view-leaderboard"),
  };

  function saveLocal() {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        rulesAccepted: state.rulesAccepted,
        teamName: state.teamName,
        members: state.members,
        assignedChallenge: state.assignedChallenge,
        totalPoints: state.totalPoints,
      })
    );
  }

  function loadLocal() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    } catch {
      return null;
    }
  }

  function clearLocal() {
    localStorage.removeItem(STORAGE_KEY);
    sessionStorage.removeItem(TOKEN_KEY);
    state.accessToken = null;
  }

  async function api(path, options = {}) {
    const headers = {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    };
    if (state.accessToken) headers.Authorization = `Bearer ${state.accessToken}`;
    const res = await fetch(`${API}${path}`, { ...options, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok && data.error) {
      const err = new Error(data.error);
      err.data = data;
      throw err;
    }
    return { res, data };
  }

  function showView(name) {
    Object.entries(views).forEach(([key, el]) => {
      if (el) el.classList.toggle("hidden", key !== name);
    });
  }

  function toast(msg, ms = 3200) {
    const el = $("#toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.add("hidden"), ms);
  }

  function openModal(title, bodyHtml, { hideClose = false } = {}) {
    $("#modal-title").textContent = title;
    $("#modal-body").innerHTML = bodyHtml;
    $("#modal-close-btn").classList.toggle("hidden", hideClose);
    $("#modal").classList.remove("hidden");
  }

  function closeModal() {
    $("#modal").classList.add("hidden");
  }

  function formatTime(total) {
    const s = Math.max(0, Math.floor(total));
    const m = String(Math.floor(s / 60)).padStart(2, "0");
    const r = String(s % 60).padStart(2, "0");
    return `${m}:${r}`;
  }

  function applySession(session) {
    if (!session) return;
    state.session = {
      remainingSeconds: Number(session.remainingSeconds) || 0,
      running: Boolean(session.running),
      ended: Boolean(session.ended),
      nextChallenge:
        session.nextChallenge == null ? null : Number(session.nextChallenge),
    };
    if (session.challenges) {
      const mapped = {};
      Object.entries(session.challenges).forEach(([key, value]) => {
        mapped[Number(key)] = value;
      });
      state.sessionChallenges = mapped;
    }
    updateHud();
    // Callers decide navigation when session.ended
  }

  function updateHud() {
    const hasTeam = Boolean(state.teamName);
    const teamWrap = $("#hud-team-wrap");
    const pointsWrap = $("#hud-points-wrap");
    if (teamWrap) teamWrap.classList.toggle("hidden", !hasTeam);
    if (pointsWrap) pointsWrap.classList.toggle("hidden", !hasTeam);
    if (hasTeam) {
      const teamEl = $("#hud-team");
      const pointsEl = $("#hud-points");
      if (teamEl) teamEl.textContent = state.teamName;
      if (pointsEl) pointsEl.textContent = state.totalPoints;
    }
    const timerEl = $("#hud-timer");
    if (timerEl) timerEl.textContent = formatTime(state.session.remainingSeconds);
    const st = $("#hud-timer-state");
    if (st) {
      if (state.session.ended) {
        st.textContent = "Ended";
        st.className = "timer-state ended";
      } else if (state.session.running) {
        st.textContent = "Running";
        st.className = "timer-state running";
      } else {
        st.textContent = "Paused";
        st.className = "timer-state";
      }
    }
    const hud = $("#session-hud");
    if (hud) hud.classList.toggle("urgent", state.session.remainingSeconds <= 300);
  }

  function endGame() {
    stopPolling();
    state.session.ended = true;
    state.session.running = false;
    updateHud();
    toast("Session time is over. The game has stopped.");
    showView("ended");
  }

  async function refreshSession() {
    const { data } = await api("/api/game/session");
    applySession(data);
    if (!state.hardened && data.ended) endGame();
    return data;
  }

  function startPolling() {
    stopPolling();
    state.pollId = setInterval(async () => {
      try {
        await refreshSession();
      } catch {
        /* ignore transient errors */
      }
    }, 1000);
  }

  function stopPolling() {
    if (state.pollId) clearInterval(state.pollId);
    state.pollId = null;
  }

  async function resumeTimer() {
    if (state.session.ended) return;
    const { data } = await api("/api/game/session/resume", { method: "POST", body: "{}" });
    applySession(data);
  }

  async function pauseTimer() {
    const { data } = await api("/api/game/session/pause", { method: "POST", body: "{}" });
    applySession(data);
  }

  function celebrate() {
    const burst = document.createElement("div");
    burst.style.cssText =
      "position:fixed;inset:0;pointer-events:none;z-index:80;overflow:hidden";
    for (let i = 0; i < 24; i += 1) {
      const bit = document.createElement("i");
      const left = Math.random() * 100;
      const color = ["#f0a06a", "#a8d4ec", "#f5d76e", "#fffefb"][i % 4];
      bit.style.cssText = `
        position:absolute;left:${left}%;top:-10px;width:8px;height:10px;
        border-radius:3px;background:${color};opacity:0.9;
        animation:fall ${1 + Math.random()}s ease-out forwards;
      `;
      burst.appendChild(bit);
    }
    const style = document.createElement("style");
    style.textContent =
      "@keyframes fall{to{transform:translateY(110vh) rotate(520deg);opacity:0}}";
    burst.appendChild(style);
    document.body.appendChild(burst);
    setTimeout(() => burst.remove(), 1600);
  }

  function allPathSolved() {
    return Array.from({ length: 10 }, (_, i) => i + 1).every(
      (id) => state.sessionChallenges[id]?.solved
    );
  }

  function resolveAssigned() {
    const n = Number(state.assignedChallenge);
    if (Number.isFinite(n) && n >= 1) return n;
    const next = Number(state.session?.nextChallenge);
    if (Number.isFinite(next) && next >= 1) return next;
    return null;
  }

  async function ensureAssignment() {
    if (state.hardened) {
      return resolveAssigned() || 1;
    }
    if (!state.teamName) return resolveAssigned();

    // Prefer existing assignment if that challenge is still open
    let current = resolveAssigned();
    const shared = current ? state.sessionChallenges[current] : null;
    if (current && !shared?.solved) {
      state.assignedChallenge = current;
      saveLocal();
      return current;
    }

    // Ask server to assign the next open challenge
    try {
      const { data } = await api("/api/game/claim", {
        method: "POST",
        body: JSON.stringify({ teamName: state.teamName }),
      });
      applySession(data.session);
      state.assignedChallenge = Number(data.assignedChallenge);
      saveLocal();
      return state.assignedChallenge;
    } catch (err) {
      console.warn("claim failed, using session nextChallenge", err);
      current = Number(state.session?.nextChallenge);
      if (Number.isFinite(current) && current >= 1) {
        state.assignedChallenge = current;
        saveLocal();
        return current;
      }
      return null;
    }
  }

  function renderRoadmap() {
    const list = $("#roadmap-list");
    if (!list) return;
    list.replaceChildren();
    const assigned = resolveAssigned();

    const banner = $("#assignment-banner");
    if (banner) {
      banner.textContent = state.hardened
        ? "جميع الصفحات مفتوحة. اختر أي ثغرة لقراءة طريقة تأمينها وتغييرات الكود واختبارات التحقق."
        : assigned
          ? `Your team owns challenge ${assigned}. Click Start challenge to begin.`
          : "No challenge assigned yet. Re-register your team or refresh the page.";
    }

    state.challengesMeta.forEach((meta) => {
      const id = Number(meta.id);
      const shared = state.sessionChallenges[id] || {};
      const isAssigned = assigned === id;
      const locked = state.hardened ? false : !shared.solved && !isAssigned;
      const card = document.createElement("div");
      card.className = "level-card";
      if (locked) card.classList.add("locked");
      if (!state.hardened && shared.solved) card.classList.add("solved");
      if (!state.hardened && isAssigned && !shared.solved) card.classList.add("active");
      const status = state.hardened
        ? "مؤمّنة"
        : shared.solved
          ? `Solved${shared.solvedBy ? ` · ${shared.solvedBy}` : ""}`
          : isAssigned
            ? "Your challenge"
            : "Waiting";
      card.innerHTML = `
        <div class="level-top">
          <span>الثغرة ${id}: ${escapeHtml(String(meta.title).split("(")[0].trim())}</span>
          <span class="lock">${escapeHtml(status)}</span>
        </div>
        <p>${escapeHtml(meta.codename)}</p>
        <span class="pts">${state.hardened ? "شرح التأمين + تغييرات الكود + اختبارات آمنة" : `+${meta.points} pts${shared.solved ? ` · ${shared.pointsEarned || 0} earned` : ""}`}</span>
      `;
      if (state.hardened || (isAssigned && !shared.solved)) {
        const start = document.createElement("button");
        start.type = "button";
        start.className = "btn btn-primary";
        start.style.marginTop = "0.75rem";
        start.textContent = state.hardened ? "افتح شرح التأمين" : "Start challenge";
        start.addEventListener("click", (e) => {
          e.preventDefault();
          e.stopPropagation();
          openChallenge(id);
        });
        card.appendChild(start);
      }
      list.appendChild(card);
    });

    const boss = $("#final-boss-card");
    if (!boss) return;
    boss.classList.toggle("hidden", state.hardened);
    if (state.hardened) return;
    const bossSolved = !!state.sessionChallenges[11]?.solved;
    boss.classList.toggle("locked", !allPathSolved());
    boss.classList.toggle("solved", bossSolved);
    const bossLock = boss.querySelector(".lock");
    if (bossLock) {
      bossLock.textContent = bossSolved ? "Solved" : allPathSolved() ? "Open" : "Locked";
    }
  }

  async function openChallenge(id) {
    id = Number(id);
    if (!state.hardened && state.session.ended) {
      endGame();
      return;
    }
    const meta = state.challengesMeta.find((c) => Number(c.id) === id);
    if (!meta) {
      toast("Challenge data not loaded. Refresh the page and try again.");
      return;
    }
    state.challengeStartedAt = Date.now();
    if (!state.hardened) {
      try {
        await resumeTimer();
      } catch (err) {
        toast(err.message || "Cannot start timer");
        if (err.data?.session?.ended) endGame();
        return;
      }
    }
    saveLocal();
    renderChallenge(meta);
    showView("challenge");
  }

  function renderChallenge(meta) {
    const root = $("#challenge-detail");
    root.replaceChildren();
    root.dir = "auto";
    const title = document.createElement("h2");
    title.textContent = `الثغرة ${meta.id}: ${meta.title}`;
    root.appendChild(title);
    const intro = document.createElement("p");
    intro.className = "guide-intro";
    intro.textContent = "هذه الصفحة توثق السلوك السابق، سبب الثغرة، التعديل الدفاعي، وطريقة التحقق أن الاستغلال أصبح محظورًا.";
    root.appendChild(intro);
    const rule = document.createElement("hr");
    rule.className = "rule";
    root.appendChild(rule);

    const addBlock = (heading, text, code = false, tone = "") => {
      const block = document.createElement("div");
      block.className = `block guide-section ${tone}`.trim();
      const label = document.createElement("h3");
      label.textContent = heading;
      const value = document.createElement(code ? "pre" : "p");
      if (code) value.className = "guide-code";
      value.textContent = text;
      block.append(label, value);
      root.appendChild(block);
    };

    const addList = (heading, values, tone = "") => {
      const block = document.createElement("section");
      block.className = `block guide-section ${tone}`.trim();
      const label = document.createElement("h3");
      label.textContent = heading;
      const list = document.createElement("ul");
      (values || []).forEach((text) => {
        const item = document.createElement("li");
        item.textContent = text;
        list.appendChild(item);
      });
      block.append(label, list);
      root.appendChild(block);
    };

    const guide = meta.guide || {};
    addBlock("واجهة API", meta.endpoint, true, "guide-endpoint");
    addBlock("قبل التأمين: ماذا كانت الثغرة؟", guide.risk_before || meta.description, false, "guide-risk");
    addBlock("السبب الجذري", guide.root_cause || meta.objective, false, "guide-cause");
    addList("كيف تم تأمينها؟", guide.controls || [], "guide-fixed");
    addList("ما الذي تغير في الكود؟", guide.code_changes || [], "guide-code-changes");

    const tests = document.createElement("section");
    tests.className = "block guide-section guide-tests";
    const testsTitle = document.createElement("h3");
    testsTitle.textContent = "كيف نختبر أن الثغرة مغلقة؟";
    tests.appendChild(testsTitle);
    (guide.tests || []).forEach((test, index) => {
      const card = document.createElement("article");
      card.className = "verification-card";
      const name = document.createElement("h4");
      name.textContent = `${index + 1}. ${test.name}`;
      const requestLabel = document.createElement("strong");
      requestLabel.textContent = "الطلب:";
      const requestCode = document.createElement("pre");
      requestCode.className = "guide-code";
      requestCode.dir = "ltr";
      requestCode.textContent = test.request;
      const expectedLabel = document.createElement("strong");
      expectedLabel.textContent = "النتيجة المتوقعة:";
      const expected = document.createElement("p");
      expected.textContent = test.expected;
      card.append(name, requestLabel, requestCode, expectedLabel, expected);
      tests.appendChild(card);
    });
    root.appendChild(tests);

    const note = document.createElement("aside");
    note.className = "guide-note";
    note.textContent = state.accessToken
      ? "هوية الاختبار جاهزة في هذا المتصفح؛ الطلبات المحمية تستطيع استخدام Bearer token الصادر لفريقك."
      : "لفحص المسارات المحمية عمليًا، ارجع للخريطة واختر «إنشاء هوية لاختبار API» للحصول على Bearer token. قراءة الشرح لا تحتاج تسجيلًا.";
    root.appendChild(note);
    clearInterval(renderChallenge._tick);
  }

  async function renderLeaderboard() {
    const { data } = await api("/api/game/leaderboard");
    applySession(data.session);
    const list = $("#leaderboard-list");
    list.replaceChildren();
    data.teams.forEach((team, idx) => {
      const li = document.createElement("li");
      if (idx === 0) li.classList.add("rank-1");
      [`${idx + 1}.`, team.name, `${team.points} pts`, formatTime(team.total_time_seconds || 0)].forEach(
        (text) => {
          const span = document.createElement("span");
          span.textContent = text;
          li.appendChild(span);
        }
      );
      list.appendChild(li);
    });
    if (!data.teams.length) {
      const empty = document.createElement("li");
      empty.textContent = "No teams yet";
      list.appendChild(empty);
    }
    const stats = data.stats || {};
    const statsRoot = $("#leaderboard-stats");
    statsRoot.replaceChildren();
    const statLines = [
      `Controls reviewed: ${stats.challengesSolved || 0} / ${stats.challengesTotal || 10}`,
      `Fastest review: ${
        stats.fastestSolve
          ? `${stats.fastestSolve.team} (${formatTime(stats.fastestSolve.seconds)})`
          : "—"
      }`,
      `Most hints used: ${stats.mostHints ? `${stats.mostHints.team} (${stats.mostHints.hints})` : "—"}`,
      `Session time left: ${formatTime(state.session.remainingSeconds)}`,
    ];
    statLines.forEach((text) => {
      const line = document.createElement("div");
      line.textContent = text;
      statsRoot.appendChild(line);
    });
  }

  function openStudentsModal(teamName) {
    state.pendingTeamName = teamName;
    $("#students-team-label").textContent = teamName;
    const wrap = $("#student-fields");
    wrap.innerHTML = "";
    addStudentField("");
    $("#students-modal").classList.remove("hidden");
  }

  function closeStudentsModal() {
    $("#students-modal").classList.add("hidden");
  }

  function addStudentField(value = "") {
    const wrap = $("#student-fields");
    const row = document.createElement("div");
    row.className = "student-row";
    const input = document.createElement("input");
    input.type = "text";
    input.name = "student";
    input.placeholder = "Student name";
    input.maxLength = 60;
    input.value = value;
    input.autocomplete = "name";
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "btn btn-ghost btn-remove";
    remove.setAttribute("aria-label", "Remove");
    remove.textContent = "Remove";
    remove.addEventListener("click", () => {
      if (wrap.children.length <= 1) {
        toast("Keep at least one student field");
        return;
      }
      row.remove();
    });
    row.appendChild(input);
    row.appendChild(remove);
    wrap.appendChild(row);
    input.focus();
  }

  async function finishRegistration(teamName, members) {
    if (!teamName) {
      toast("Team name missing. Go back and enter it again.");
      return;
    }
    const submitBtn = $("#students-form button[type='submit']");
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "Starting…";
    }
    try {
      const { data } = await api("/api/game/register", {
        method: "POST",
        body: JSON.stringify({ teamName, members }),
      });
      state.accessToken = data.accessToken;
      sessionStorage.setItem(TOKEN_KEY, state.accessToken);
      state.teamName = data.team.name;
      state.members = members;
      state.assignedChallenge = Number(
        data.assignedChallenge ?? data.team.assigned_challenge
      );
      if (!Number.isFinite(state.assignedChallenge) || state.assignedChallenge < 1) {
        state.assignedChallenge = null;
      }
      state.totalPoints = data.team.points || 0;
      state.rulesAccepted = true;
      applySession(data.session);
      saveLocal();
      closeStudentsModal();
      await ensureAssignment();
      showView("roadmap");
      renderRoadmap();
      toast(data.message || `Registered for challenge ${state.assignedChallenge}`);
      // Stay on roadmap — students click Start challenge themselves
    } catch (err) {
      console.error(err);
      toast(err.message || "Registration failed");
      if (!state.hardened && err.data?.session?.ended) {
        closeStudentsModal();
        endGame();
      }
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = "Continue to challenge";
      }
    }
  }

  function resetToNextTeam() {
    sessionStorage.removeItem(TOKEN_KEY);
    state.accessToken = null;
    state.teamName = null;
    state.members = [];
    state.assignedChallenge = null;
    state.totalPoints = 0;
    state.challengeStartedAt = null;
    saveLocal();
    updateHud();
    showView("register");
    refreshAssignPreview();
  }

  async function refreshAssignPreview() {
    try {
      const session = await refreshSession();
      const el = $("#assign-preview");
      if (!el) return;
      if (state.hardened) {
        el.textContent = "التسجيل اختياري وينشئ ملفًا معزولًا وBearer token لتجربة الطلبات المحمية.";
      } else if (session.ended) {
        el.textContent = "Session has ended.";
      } else if (session.nextChallenge == null) {
        el.textContent = "All challenges are complete.";
      } else if (session.nextChallenge === 11) {
        el.textContent = "Next up: Final boss.";
      } else {
        el.textContent = `Next open challenge on the shared path: Level ${session.nextChallenge}.`;
      }
    } catch {
      /* ignore */
    }
  }

  function bindActions() {
    $("#register-form").addEventListener("submit", (e) => {
      e.preventDefault();
      if (!state.hardened && state.session.ended) {
        endGame();
        return;
      }
      const name = $("#team-input").value.trim();
      if (!name) return;
      openStudentsModal(name);
    });

    $("#add-student-btn").addEventListener("click", () => addStudentField(""));

    $("#students-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const inputs = [...$("#student-fields").querySelectorAll("input")];
      const members = inputs.map((i) => i.value.trim()).filter(Boolean);
      if (!members.length) {
        toast("Add at least one student name");
        return;
      }
      await finishRegistration(state.pendingTeamName, members);
    });

    document.body.addEventListener("click", async (e) => {
      const btn = e.target.closest("[data-action]");
      if (!btn) return;
      const action = btn.dataset.action;

      if (action === "accept-rules") {
        state.rulesAccepted = true;
        saveLocal();
        if (state.hardened) {
          renderRoadmap();
          showView("roadmap");
        } else {
          await refreshAssignPreview();
          showView("register");
        }
      }
      if (action === "cancel-students") {
        closeStudentsModal();
      }
      if (action === "next-team") {
        resetToNextTeam();
      }
      if (action === "back-roadmap") {
        if (!state.hardened && !state.session.ended) await pauseTimer();
        showView("roadmap");
        renderRoadmap();
      }
      if (action === "back-from-leaderboard") {
        if (!state.hardened && state.session.ended) {
          showView("ended");
          return;
        }
        if (state.hardened || state.teamName) {
          showView("roadmap");
          renderRoadmap();
        } else {
          showView("register");
        }
      }
      if (action === "open-leaderboard") {
        await renderLeaderboard();
        showView("leaderboard");
      }
      if (action === "close-modal") closeModal();
      if (action === "hints-help") {
        openModal(
          "Hardened mode",
          `<ul>
            <li>كل الثغرات العشر مفتوحة للشرح دون تسجيل أو مؤقت.</li>
            <li>أنشئ هوية اختبار فقط للحصول على Bearer token للمسارات المحمية.</li>
            <li>إرسال Flags وFinal Boss متقاعدان بعد التأمين.</li>
          </ul>`
        );
      }
      if (action === "open-requests") {
        const meta = state.challengesMeta.map((c) => escapeHtml(`${c.id}. ${c.endpoint}`));
        openModal(
          "مسارات التحقق",
          `<p>استخدم <code>http://127.0.0.1:5000</code>، ومع Bearer token عند اختبار المسارات المحمية.</p>
           <pre>${meta.join("\n")}</pre>`
        );
      }
      if (action === "full-reset") {
        if (state.hardened) {
          if (!confirm("العودة إلى بداية دليل التأمين؟\n\nسيتم مسح حالة العرض ورمز الاختبار من هذا المتصفح فقط. لن تُمسح قاعدة البيانات ولن تحتاج رمز المدير.")) {
            return;
          }
          stopPolling();
          clearLocal();
          location.reload();
          return;
        }
        if (
          !confirm(
            "Clear the whole session?\n\nThis resets the 100-minute timer, all teams, scores, and challenge progress. You will start from the rules page again."
          )
        ) {
          return;
        }
        const adminToken = prompt("Enter the administrator token for this one-time reset:");
        if (!adminToken) return;
        try {
          await api("/api/game/restart", {
            method: "POST",
            headers: { "X-Admin-Token": adminToken },
            body: JSON.stringify({ fullReset: true }),
          });
        } catch (err) {
          toast(err.message || "Administrator reset failed");
          return;
        }
        stopPolling();
        clearLocal();
        toast("Session cleared. Starting over…");
        setTimeout(() => location.reload(), 400);
      }
    });

  }

  async function boot() {
    bindActions();
    const { data } = await api("/api/challenges");
    state.challengesMeta = data.challenges;
    state.hardened = data.mode === "hardened";
    document.body.classList.toggle("hardened-mode", state.hardened);
    if (!state.hardened) startPolling();
    await refreshSession();

    if (!state.hardened && state.session.ended) {
      showView("ended");
      return;
    }

    const saved = loadLocal();
    if (saved?.rulesAccepted && saved?.teamName) {
      state.rulesAccepted = true;
      state.teamName = saved.teamName;
      state.members = saved.members || [];
      state.assignedChallenge = saved.assignedChallenge;
      state.totalPoints = saved.totalPoints || 0;
      try {
        const { data: st } = await api(`/api/game/state/${encodeURIComponent(state.teamName)}`);
        applySession(st.session);
        state.totalPoints = st.team.points;
        state.members = st.team.members || state.members;
        const rawAssigned = st.team.assigned_challenge ?? state.assignedChallenge;
        state.assignedChallenge =
          rawAssigned != null && Number(rawAssigned) >= 1 ? Number(rawAssigned) : null;
        await ensureAssignment();
        updateHud();
        renderRoadmap();
        showView("roadmap");
      } catch {
        clearLocal();
        if (state.hardened) {
          state.rulesAccepted = true;
          saveLocal();
          renderRoadmap();
          showView("roadmap");
        } else {
          showView("rules");
        }
      }
    } else if (saved?.rulesAccepted) {
      state.rulesAccepted = true;
      if (state.hardened) {
        renderRoadmap();
        showView("roadmap");
      } else {
        showView("register");
        refreshAssignPreview();
      }
    } else {
      showView("rules");
    }
  }

  boot().catch((err) => {
    console.error(err);
    toast("Failed to reach API. Is the server running on :5000?");
  });
})();
