// web/plugin.jsx
import { platform } from "@oie/web-shell";
var React = platform.React;
var api = platform.api;
var { toast, taskButton } = platform.ui;
var EXT = "/extensions/oidcauth";
var fields = [
  ["discovery-url", "Discovery URL", "url"],
  ["client-id", "Client ID", "text"],
  ["username-claim", "Username claim", "text"],
  ["username-prefix", "Username prefix", "text"],
  ["jit.email-claim", "Email claim", "text"],
  ["jit.name-claim", "Name claim", "text"],
  ["jit.organization-claim", "Organization claim", "text"],
  ["allowed-algorithms", "Allowed algorithms", "text"],
  ["clock-skew-seconds", "Clock skew (seconds)", "number"],
  ["max-token-age-seconds", "Maximum token age (seconds)", "number"],
  ["jwks-cache-ttl-seconds", "JWKS cache TTL (seconds)", "number"],
  ["roles.claim", "Roles claim", "text"],
  ["roles.default", "Default role", "text"]
];
var parsePairs = (value) => String(value || "").split(",").map((s) => s.trim()).filter(Boolean).map((item) => {
  const i = item.indexOf("=");
  return i > 0 ? { k: item.slice(0, i).trim(), v: item.slice(i + 1).trim() } : { k: item.trim(), v: "" };
});
var serializePairs = (rows) => rows.filter((r) => r.k.trim() && r.v.trim()).map((r) => `${r.k.trim()}=${r.v.trim()}`).join(",");
function PairEditor({ label, value, onChange, disabled, keyPlaceholder, valuePlaceholder, addLabel }) {
  const [rows, setRows] = React.useState(() => parsePairs(value));
  const last = React.useRef(value);
  React.useEffect(() => {
    if (value !== last.current) {
      last.current = value;
      setRows(parsePairs(value));
    }
  }, [value]);
  const commit = (next) => {
    setRows(next);
    const s = serializePairs(next);
    if (s !== last.current) {
      last.current = s;
      onChange(s);
    }
  };
  const edit = (i, part, text) => commit(rows.map((r, at) => at === i ? { ...r, [part]: text.replace(/[,=]/g, "") } : r));
  return /* @__PURE__ */ React.createElement("div", { className: "field" }, /* @__PURE__ */ React.createElement("label", null, label), rows.map((row, i) => /* @__PURE__ */ React.createElement("div", { key: i, style: { display: "flex", gap: 8, alignItems: "center", marginBottom: 8 } }, /* @__PURE__ */ React.createElement("input", { style: { flex: 1 }, type: "text", value: row.k, placeholder: keyPlaceholder, disabled, onChange: (e) => edit(i, "k", e.target.value) }), /* @__PURE__ */ React.createElement("span", { className: "text-text-faint" }, "\u2192"), /* @__PURE__ */ React.createElement("input", { style: { flex: 1 }, type: "text", value: row.v, placeholder: valuePlaceholder, disabled, onChange: (e) => edit(i, "v", e.target.value) }), /* @__PURE__ */ React.createElement("button", { className: "btn", type: "button", disabled, title: "Remove", onClick: () => commit(rows.filter((_, at) => at !== i)) }, "\xD7"))), /* @__PURE__ */ React.createElement("button", { className: "btn", type: "button", disabled, onClick: () => {
    setRows([...rows, { k: "", v: "" }]);
  } }, addLabel));
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
  const save = React.useCallback(async () => {
    try {
      await api.put(`${EXT}/configuration`, { string: JSON.stringify(form) });
      setForm(decode(await api.get(`${EXT}/configuration`)));
      toast("OIDC configuration saved.", "success");
      markClean();
      return true;
    } catch (e) {
      toast(e.message || "OIDC configuration could not be saved.", "error");
      return false;
    }
  }, [form, markClean]);
  const saveRef = React.useRef(save);
  saveRef.current = save;
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
          toast(`OIDC discovery succeeded: ${r.issuer || "issuer verified"}`, "success");
        } catch (e) {
          toast(e.message || "OIDC connection test failed.", "error");
        }
      })
    ]);
  }, [load, setTasks]);
  React.useEffect(() => setSave(() => save), [save, setSave]);
  const patch = (key, value) => {
    setForm((f) => ({ ...f, [key]: value }));
    markDirty();
  };
  if (error) return /* @__PURE__ */ React.createElement("div", { className: "p-4", style: { color: "var(--err)" } }, error);
  if (!form) return /* @__PURE__ */ React.createElement("div", { className: "p-4 text-text-faint" }, "Loading\u2026");
  return /* @__PURE__ */ React.createElement("div", { className: "p-4", style: { maxWidth: 820 } }, /* @__PURE__ */ React.createElement("div", { className: "mb-4" }, /* @__PURE__ */ React.createElement("label", { className: "check" }, /* @__PURE__ */ React.createElement("input", { type: "checkbox", checked: String(form.enabled) === "true", onChange: (e) => patch("enabled", String(e.target.checked)) }), "Enable OIDC login")), /* @__PURE__ */ React.createElement("div", { className: "grid grid-cols-2 gap-4" }, fields.map(([key, label, type]) => /* @__PURE__ */ React.createElement("div", { className: "field", key }, /* @__PURE__ */ React.createElement("label", null, label), /* @__PURE__ */ React.createElement("input", { type, value: form[key] || "", onChange: (e) => patch(key, e.target.value), disabled: String(form.enabled) !== "true" }))), /* @__PURE__ */ React.createElement("div", { className: "field" }, /* @__PURE__ */ React.createElement("label", null, "JIT provision unknown users"), /* @__PURE__ */ React.createElement("select", { value: form["jit.enabled"] || "false", onChange: (e) => patch("jit.enabled", e.target.value), disabled: String(form.enabled) !== "true" }, /* @__PURE__ */ React.createElement("option", { value: "true" }, "Yes"), /* @__PURE__ */ React.createElement("option", { value: "false" }, "No"))), /* @__PURE__ */ React.createElement("div", { className: "field" }, /* @__PURE__ */ React.createElement("label", null, "Role synchronization"), /* @__PURE__ */ React.createElement("select", { value: form["roles.sync"] || "always", onChange: (e) => patch("roles.sync", e.target.value), disabled: String(form.enabled) !== "true" }, /* @__PURE__ */ React.createElement("option", { value: "always" }, "Every login"), /* @__PURE__ */ React.createElement("option", { value: "jit-only" }, "JIT only"), /* @__PURE__ */ React.createElement("option", { value: "never" }, "Never"))), /* @__PURE__ */ React.createElement("div", { className: "field" }, /* @__PURE__ */ React.createElement("label", null, "Infer roles by name"), /* @__PURE__ */ React.createElement("select", { value: form["roles.infer"] || "false", onChange: (e) => patch("roles.infer", e.target.value), disabled: String(form.enabled) !== "true" }, /* @__PURE__ */ React.createElement("option", { value: "false" }, "No \u2014 mapped claims only"), /* @__PURE__ */ React.createElement("option", { value: "true" }, "Yes \u2014 claim values matching a role name")))), /* @__PURE__ */ React.createElement("div", { className: "mt-4", style: { maxWidth: 560 } }, /* @__PURE__ */ React.createElement(
    PairEditor,
    {
      label: "Claim-to-role mappings",
      value: form["roles.map"] || "",
      disabled: String(form.enabled) !== "true",
      keyPlaceholder: "claim value (e.g. oie-admins)",
      valuePlaceholder: "RBAC role (e.g. Administrator)",
      addLabel: "Add mapping",
      onChange: (v) => patch("roles.map", v)
    }
  ), /* @__PURE__ */ React.createElement(
    PairEditor,
    {
      label: "Linked accounts",
      value: form["linked-accounts"] || "",
      disabled: String(form.enabled) !== "true",
      keyPlaceholder: "engine username",
      valuePlaceholder: "issuer#subject",
      addLabel: "Link account",
      onChange: (v) => patch("linked-accounts", v)
    }
  )));
}
async function register(host) {
  try {
    let raw = await api.get("/extensions/rbac/my-permissions");
    if (raw && typeof raw === "object" && !Array.isArray(raw)) raw = raw.string;
    const permissions = new Set((raw == null || raw === "" ? [] : Array.isArray(raw) ? raw : [raw]).map(String));
    if (!permissions.has("manageOIDC")) return;
  } catch (e) {
    if (!(e && (e.status === 404 || e.status === 501))) {
      console.warn("[oidcauth] permission load failed \u2014 hiding settings panel:", e);
      return;
    }
  }
  host.registerSettingsPanel({ label: "OIDC Authentication", order: 80, component: OidcPanel });
}
export {
  register
};
