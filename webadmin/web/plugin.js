// web/plugin.jsx
import { platform } from "@oie/web-shell";
var React = platform.React;
var api = platform.api;
var { toast, taskButton } = platform.ui;
var EXT = "/extensions/oidcauth";
var nextRowId = 0;
var CHOICE_LABELS = { "jit.enabled": { true: "Yes", false: "No" }, "roles.infer": { false: "No \u2014 mapped claims only", true: "Yes \u2014 claim values matching a role name" }, "roles.sync": { always: "Every login", "jit-only": "JIT only", never: "Never" } };
var choiceLabel = (key, value) => CHOICE_LABELS[key] && CHOICE_LABELS[key][value] || value;
var truthy = (value) => ["true", "yes", "on", "1"].includes(String(value == null ? "" : value).trim().toLowerCase());
var parsePairs = (value) => String(value || "").split(",").map((s) => s.trim()).filter(Boolean).map((item) => {
  const i = item.indexOf("=");
  return { id: ++nextRowId, ...i > 0 ? { k: item.slice(0, i).trim(), v: item.slice(i + 1).trim() } : { k: item.trim(), v: "" } };
});
var serializePairs = (rows, isBlank = (v) => !String(v || "").trim()) => rows.filter((r) => r.k.trim() && !isBlank(r.v)).map((r) => `${r.k.trim()}=${r.v.trim()}`).join(",");
var pairProblem = (rows, isBlank = (v) => !String(v || "").trim()) => {
  if (rows.some((r) => !!r.k.trim() !== !isBlank(r.v))) return "Every row needs both a key and a value \u2014 fill the blank one in, or remove the row.";
  const keys = rows.map((r) => r.k.trim()).filter(Boolean);
  const duplicate = keys.find((k, i) => keys.indexOf(k) !== i);
  return duplicate ? `"${duplicate}" appears more than once \u2014 only the last would take effect.` : null;
};
function ChoiceSelect({ value, options, placeholder, unknownLabel, disabled, onChange, style }) {
  const current = String(value || "");
  return /* @__PURE__ */ React.createElement("select", { style, value: current, disabled, onChange: (e) => onChange(e.target.value) }, /* @__PURE__ */ React.createElement("option", { value: "" }, placeholder || "\u2014 choose \u2014"), options.map((o) => /* @__PURE__ */ React.createElement("option", { key: o, value: o }, o)), current && !options.includes(current) ? /* @__PURE__ */ React.createElement("option", { value: current }, current, " ", unknownLabel || "(unknown)") : null);
}
var listOf = (raw, key) => {
  const inner = raw && typeof raw === "object" && !Array.isArray(raw) && raw.list ? raw.list : raw;
  const items = inner && typeof inner === "object" && !Array.isArray(inner) && inner[key] !== void 0 ? inner[key] : inner;
  return Array.isArray(items) ? items : items && typeof items === "object" ? [items] : [];
};
var roleNamesOf = (raw) => listOf(raw, "com.diridium.rbac.Role").map((r) => r && r.name).filter(Boolean);
var userNamesOf = (raw) => listOf(raw, "user").map((u) => u && u.username).filter(Boolean);
var SUGGESTIONS = (form) => ({
  "username-claim": ["preferred_username", "email", "upn", "unique_name", "sub"],
  "jit.email-claim": ["email", "upn", "mail"],
  "jit.name-claim": ["name", "given_name", "family_name", "display_name"],
  "jit.organization-claim": ["organization", "org", "company"],
  "roles.claim": ["groups", "roles", "realm_access.roles", `resource_access.${String(form["client-id"] || "").trim() || "<client-id>"}.roles`]
});
var ADVANCED = /* @__PURE__ */ new Set(["jit.email-claim", "jit.name-claim", "jit.organization-claim", "allowed-algorithms", "clock-skew-seconds", "max-token-age-seconds", "jwks-cache-ttl-seconds"]);
function PairEditor({ label, value, onChange, onProblem, disabled, keyPlaceholder, keyOptions, keyUnknownLabel, valuePlaceholder, valueOptions, valueUnknownLabel, valuePrefix, valueCheck, addLabel }) {
  const [rows, setRows] = React.useState(() => parsePairs(value));
  const last = React.useRef(value);
  React.useEffect(() => {
    if (value !== last.current) {
      last.current = value;
      setRows(parsePairs(value));
    }
  }, [value]);
  const isBlank = (v) => {
    const t = String(v || "").trim();
    return !t || !!valuePrefix && t === valuePrefix;
  };
  const problem = disabled ? null : rows.filter((r) => r.k.trim()).map((r) => valueCheck ? valueCheck(r.v) : null).find(Boolean) || pairProblem(rows, isBlank);
  React.useEffect(() => {
    onProblem(problem);
    return () => onProblem(null);
  }, [problem, onProblem]);
  const commit = (next) => {
    setRows(next);
    const s = serializePairs(next, isBlank);
    if (s !== last.current) {
      last.current = s;
      onChange(s);
    }
  };
  const edit = (id, part, text) => commit(rows.map((r) => r.id === id ? { ...r, [part]: part === "k" ? text.replace(/[,=]/g, "") : text.replace(/,/g, "") } : r));
  return /* @__PURE__ */ React.createElement("div", { className: "field" }, /* @__PURE__ */ React.createElement("label", null, label), rows.map((row) => /* @__PURE__ */ React.createElement("div", { key: row.id, style: { display: "flex", gap: 8, alignItems: "center", marginBottom: 8 } }, Array.isArray(keyOptions) ? /* @__PURE__ */ React.createElement(ChoiceSelect, { style: { flex: 1 }, value: row.k, options: keyOptions, placeholder: keyPlaceholder, unknownLabel: keyUnknownLabel, disabled, onChange: (v) => edit(row.id, "k", v) }) : /* @__PURE__ */ React.createElement("input", { style: { flex: 1 }, type: "text", value: row.k, placeholder: keyPlaceholder, disabled, onChange: (e) => edit(row.id, "k", e.target.value) }), /* @__PURE__ */ React.createElement("span", { className: "text-text-faint" }, "\u2192"), Array.isArray(valueOptions) ? /* @__PURE__ */ React.createElement(ChoiceSelect, { style: { flex: 1 }, value: row.v, options: valueOptions, placeholder: valuePlaceholder, unknownLabel: valueUnknownLabel, disabled, onChange: (v) => edit(row.id, "v", v) }) : /* @__PURE__ */ React.createElement("input", { style: { flex: 1 }, type: "text", value: row.v, placeholder: valuePlaceholder, disabled, onChange: (e) => edit(row.id, "v", e.target.value) }), /* @__PURE__ */ React.createElement("button", { className: "btn", type: "button", disabled, title: "Remove", onClick: () => commit(rows.filter((r) => r.id !== row.id)) }, "\xD7"))), /* @__PURE__ */ React.createElement("button", { className: "btn", type: "button", disabled, onClick: () => {
    setRows([...rows, { id: ++nextRowId, k: "", v: valuePrefix || "" }]);
  } }, addLabel), problem ? /* @__PURE__ */ React.createElement("div", { style: { color: "var(--err)", fontSize: 12, marginTop: 4 } }, problem) : null);
}
var decode = (value) => {
  if (typeof value === "string") return value ? JSON.parse(value) : {};
  return value && typeof value === "object" ? typeof value.string === "string" ? JSON.parse(value.string) : value : {};
};
function OidcPanel({ setTasks, setSave, markDirty, markClean }) {
  const [form, setForm] = React.useState(null), [error, setError] = React.useState("");
  const formRef = React.useRef(null);
  formRef.current = form;
  const load = React.useCallback(async () => {
    try {
      setForm(decode(await api.get(`${EXT}/configuration`)));
      setError("");
      markClean();
    } catch (e) {
      setError(e.message || "Failed to load OIDC configuration.");
    }
  }, [markClean]);
  const [pairProblems, setPairProblems] = React.useState({});
  const problemHandlers = React.useRef({});
  const noteProblem = React.useCallback((which) => {
    if (!problemHandlers.current[which]) problemHandlers.current[which] = (problem) => setPairProblems((p) => p[which] === problem ? p : { ...p, [which]: problem });
    return problemHandlers.current[which];
  }, []);
  const problemsRef = React.useRef(pairProblems);
  problemsRef.current = pairProblems;
  const save = React.useCallback(async () => {
    const blocking = Object.values(problemsRef.current).filter(Boolean);
    if (blocking.length) {
      toast(blocking[0], "error");
      return false;
    }
    try {
      await api.put(`${EXT}/configuration`, { string: JSON.stringify(form) });
    } catch (e) {
      toast(e.message || "OIDC configuration could not be saved.", "error");
      return false;
    }
    markClean();
    try {
      setForm(decode(await api.get(`${EXT}/configuration`)));
      toast("OIDC configuration saved.", "success");
    } catch (e) {
      toast(`OIDC configuration saved, but the tab could not re-read it: ${e.message || "refresh to confirm."}`, "warn");
    }
    return true;
  }, [form, markClean]);
  const saveRef = React.useRef(save);
  saveRef.current = save;
  const [roleNames, setRoleNames] = React.useState(null);
  React.useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const names = roleNamesOf(await api.get("/extensions/rbac/roles"));
        if (alive && names.length) setRoleNames(names);
      } catch (e) {
      }
    })();
    return () => {
      alive = false;
    };
  }, []);
  const [userNames, setUserNames] = React.useState(null);
  React.useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const names = userNamesOf(await api.get("/users"));
        if (alive && names.length) setUserNames(names);
      } catch (e) {
      }
    })();
    return () => {
      alive = false;
    };
  }, []);
  const [issuer, setIssuer] = React.useState("");
  React.useEffect(() => {
    load();
  }, []);
  React.useEffect(() => {
    setTasks("OIDC Authentication Tasks", [
      taskButton("Save", "save", () => saveRef.current(), { primary: true, task: "doSave", group: "settings_OIDC Authentication" }),
      taskButton("Refresh", "refresh", load),
      taskButton("Test connection", "check", async () => {
        try {
          const r = decode(await api.post(`${EXT}/test`, { string: JSON.stringify(formRef.current) }));
          if (r.issuer) setIssuer(String(r.issuer));
          toast(`OIDC verified: ${r.issuer || "issuer"} \u2014 ${r.keyCount || 0} signing key(s) reachable`, "success");
        } catch (e) {
          toast(e.message || "OIDC connection test failed.", "error");
        }
      })
    ]);
  }, [load, setTasks]);
  React.useEffect(() => {
    setSave(save);
  }, [save, setSave]);
  const patch = (key, value) => {
    setForm((f) => ({ ...f, [key]: value }));
    markDirty();
  };
  if (error) return /* @__PURE__ */ React.createElement("div", { className: "p-4", style: { color: "var(--err)" } }, error);
  if (!form) return /* @__PURE__ */ React.createElement("div", { className: "p-4 text-text-faint" }, "Loading\u2026");
  const pinned = Array.isArray(form._pinned) ? form._pinned : [];
  const schema = Array.isArray(form._schema) ? form._schema : [];
  const locked = (key) => key !== "enabled" && !truthy(form.enabled) || pinned.includes(key);
  const pinnedNote = (key) => pinned.includes(key) ? /* @__PURE__ */ React.createElement("span", { className: "text-text-faint", style: { fontWeight: "normal" } }, " \u2014 pinned") : null;
  return /* @__PURE__ */ React.createElement("div", { className: "p-4", style: { maxWidth: 820 } }, String(form._killSwitch) === "true" ? /* @__PURE__ */ React.createElement("div", { className: "mb-4 p-2", style: { border: "1px solid var(--err)", borderRadius: 6, color: "var(--err)" } }, /* @__PURE__ */ React.createElement("strong", null, "SSO is switched off by the emergency kill switch."), " The engine is refusing every OIDC sign-in and no longer advertises SSO to the login screen, whatever this form says. Clear ", /* @__PURE__ */ React.createElement("code", null, "OIE_OIDC_DISABLED"), " (or the ", /* @__PURE__ */ React.createElement("code", null, "org.openintegrationengine.oidc.disabled"), " system property) and restart to re-enable.") : null, form._error ? /* @__PURE__ */ React.createElement("div", { className: "mb-4 p-2", style: { border: "1px solid var(--err)", borderRadius: 6, color: "var(--err)" } }, /* @__PURE__ */ React.createElement("strong", null, "This policy is not in force."), " The engine rejected it at load: ", form._error, " Until it parses, the login screen offers no SSO button and sign-in attempts are told SSO is disabled.") : null, pinned.length ? /* @__PURE__ */ React.createElement("div", { className: "mb-4 p-2", style: { border: "1px solid var(--line)", borderRadius: 6 } }, "Pinned by the operator environment \u2014 an ", /* @__PURE__ */ React.createElement("code", null, "OIE_OIDC_*"), " variable or system property overrides these, so they are shown read-only and saving leaves the stored policy untouched: ", /* @__PURE__ */ React.createElement("strong", null, pinned.join(", "))) : null, /* @__PURE__ */ React.createElement("div", { className: "mb-4 text-text-faint", style: { fontSize: 12 } }, "Redirect URI to register with your provider: ", /* @__PURE__ */ React.createElement("code", null, form._redirectUri || "<web-administrator-origin>/oidc/callback")), schema.filter((f) => f.key === "enabled").map((f) => /* @__PURE__ */ React.createElement("div", { className: "mb-4", key: f.key }, /* @__PURE__ */ React.createElement("label", { className: "check" }, /* @__PURE__ */ React.createElement(
    "input",
    {
      type: "checkbox",
      checked: truthy(form.enabled),
      disabled: locked(f.key),
      onChange: (e) => patch("enabled", String(e.target.checked))
    }
  ), f.label, pinnedNote(f.key)))), (() => {
    const suggest = SUGGESTIONS(form);
    const renderField = (f) => /* @__PURE__ */ React.createElement("div", { className: "field", key: f.key }, /* @__PURE__ */ React.createElement("label", null, f.label, pinnedNote(f.key)), f.kind === "boolean" || f.kind === "enum" ? /* @__PURE__ */ React.createElement("select", { value: form[f.key] || "", disabled: locked(f.key), onChange: (e) => patch(f.key, e.target.value) }, (f.kind === "boolean" ? ["true", "false"] : f.choices || []).map((c) => /* @__PURE__ */ React.createElement("option", { key: c, value: c }, choiceLabel(f.key, c)))) : f.key === "roles.default" && roleNames ? /* @__PURE__ */ React.createElement(ChoiceSelect, { value: form[f.key] || "", options: roleNames, placeholder: "\u2014 no default role \u2014", unknownLabel: "(not an existing role)", disabled: locked(f.key), onChange: (v) => patch(f.key, v) }) : /* @__PURE__ */ React.createElement(
      "input",
      {
        type: f.kind === "number" ? "number" : f.kind === "url" ? "url" : "text",
        value: form[f.key] || "",
        list: suggest[f.key] ? `oidc-suggest-${f.key}` : void 0,
        disabled: locked(f.key),
        onChange: (e) => patch(f.key, e.target.value)
      }
    ), suggest[f.key] ? /* @__PURE__ */ React.createElement("datalist", { id: `oidc-suggest-${f.key}` }, suggest[f.key].map((s) => /* @__PURE__ */ React.createElement("option", { key: s, value: s }))) : null);
    const issuerGuess = issuer || String(form["discovery-url"] || "").trim().replace(/\/\.well-known\/openid-configuration\/?$/, "");
    const subjectCheck = (v) => /#\s*$/.test(String(v || "")) ? `Paste the subject after "#" \u2014 the identifier your provider shows for this user (in Keycloak, the user's ID).` : null;
    return /* @__PURE__ */ React.createElement(React.Fragment, null, /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-4" }, schema.filter((f) => f.key !== "enabled" && f.kind !== "pairs" && !ADVANCED.has(f.key)).map(renderField)), /* @__PURE__ */ React.createElement("div", { className: "mt-4", style: { maxWidth: 560 } }, schema.filter((f) => f.kind === "pairs").map((f) => /* @__PURE__ */ React.createElement(
      PairEditor,
      {
        key: f.key,
        label: f.label + (pinned.includes(f.key) ? " \u2014 pinned" : ""),
        value: form[f.key] || "",
        disabled: locked(f.key),
        addLabel: f.key === "roles.map" ? "Add mapping" : "Link account",
        keyPlaceholder: f.key === "roles.map" ? "claim value (e.g. oie-admins)" : userNames ? "\u2014 choose a user \u2014" : "engine username",
        keyOptions: f.key === "linked-accounts" ? userNames : void 0,
        keyUnknownLabel: "(no such user)",
        valuePlaceholder: f.key === "roles.map" ? roleNames ? "\u2014 choose a role \u2014" : "RBAC role (e.g. Administrator)" : "issuer#subject",
        valueOptions: f.key === "roles.map" ? roleNames : void 0,
        valueUnknownLabel: "(not an existing role)",
        valuePrefix: f.key === "linked-accounts" && issuerGuess ? `${issuerGuess}#` : "",
        valueCheck: f.key === "linked-accounts" ? subjectCheck : void 0,
        onChange: (v) => patch(f.key, v),
        onProblem: noteProblem(f.key)
      }
    ))), /* @__PURE__ */ React.createElement("details", { className: "mt-4" }, /* @__PURE__ */ React.createElement("summary", { style: { cursor: "pointer", fontWeight: 600 } }, "Advanced"), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-4 mt-2" }, schema.filter((f) => ADVANCED.has(f.key)).map(renderField))));
  })());
}
async function register(host) {
  try {
    await api.get(`${EXT}/configuration`);
  } catch (e) {
    if (e && e.status === 403) {
      console.warn("[oidcauth] manageOIDC not granted \u2014 hiding settings panel");
      return;
    }
    console.warn("[oidcauth] permission probe inconclusive \u2014 showing settings panel:", e);
  }
  host.registerSettingsPanel({ label: "OIDC Authentication", order: 80, component: OidcPanel });
}
export {
  register
};
