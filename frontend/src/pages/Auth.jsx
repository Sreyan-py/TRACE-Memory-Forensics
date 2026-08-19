import { useState } from "react";
import {
  Shield, Lock, User, AlertTriangle, ArrowRight, Eye, EyeOff,
  Check, X, KeyRound, ChevronLeft,
} from "lucide-react";
import { authApi, storeToken, storeUsername } from "../services/api";

// ─────────────────────────────────────────────────────────────────────────────
// Password strength checker
// ─────────────────────────────────────────────────────────────────────────────
function getPasswordCriteria(pw) {
  return {
    length:  pw.length >= 8,
    upper:   /[A-Z]/.test(pw),
    lower:   /[a-z]/.test(pw),
    number:  /[0-9]/.test(pw),
    special: /[!@#$%^&*(),.?":{}|<>]/.test(pw),
  };
}

function allCriteriaMet(criteria) {
  return Object.values(criteria).every(Boolean);
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared UI primitives
// ─────────────────────────────────────────────────────────────────────────────
function sanitizeAuthError(msg, defaultMsg = "Authentication failure. Please try again.") {
  if (!msg) return "";
  const lower = String(msg).toLowerCase();
  if (
    lower.includes("analysis") ||
    lower.includes("volatility") ||
    lower.includes("memory image") ||
    lower.includes("memory dump") ||
    lower.includes("symbols") ||
    lower.includes("unsupported")
  ) {
    return defaultMsg;
  }
  return msg;
}

function ErrorBox({ message }) {
  if (!message) return null;
  const safeMsg = sanitizeAuthError(message, "Authentication failure. Please try again.");
  return (
    <div className="bg-red-500/10 border border-red-500/20 p-4 rounded-xl flex items-start gap-3">
      <AlertTriangle size={16} className="text-red-400 shrink-0 mt-0.5" />
      <span className="text-[10px] text-red-400 font-black uppercase tracking-widest leading-snug whitespace-pre-line">
        {safeMsg}
      </span>
    </div>
  );
}

function SuccessBox({ message }) {
  if (!message) return null;
  return (
    <div className="bg-green-500/10 border border-green-500/20 p-4 rounded-xl flex items-start gap-3">
      <Check size={16} className="text-green-400 shrink-0 mt-0.5" />
      <span className="text-[10px] text-green-400 font-black uppercase tracking-widest leading-snug">
        {message}
      </span>
    </div>
  );
}

function CyberInput({ icon: Icon, label, type = "text", value, onChange, placeholder, required, rightElement }) {
  return (
    <div>
      {label && (
        <label className="block text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
          <Icon size={12} /> {label}
        </label>
      )}
      <div className="relative">
        <input
          type={type}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          required={required}
          className="w-full bg-black/40 border border-white/10 rounded-2xl px-6 py-4 text-white focus:border-cyan-500 outline-none transition-all pl-12 pr-12"
        />
        <Icon className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-600" size={18} />
        {rightElement && (
          <div className="absolute right-4 top-1/2 -translate-y-1/2">
            {rightElement}
          </div>
        )}
      </div>
    </div>
  );
}

function SubmitButton({ loading, label, loadingLabel }) {
  return (
    <button
      type="submit"
      disabled={loading}
      className="w-full bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black py-5 rounded-2xl font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(34,211,238,0.3)] mt-6 cursor-pointer"
    >
      {loading ? loadingLabel : label}
      {!loading && <ArrowRight size={16} />}
    </button>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Remember Device Modal
// ─────────────────────────────────────────────────────────────────────────────
function RememberDeviceModal({ onSave, onSkip }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0b1020] border border-white/10 rounded-3xl p-8 max-w-sm w-full shadow-2xl relative overflow-hidden">
        <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:20px_20px] pointer-events-none" />
        <div className="flex justify-center mb-6">
          <div className="w-14 h-14 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-2xl flex items-center justify-center shadow-[0_0_25px_rgba(34,211,238,0.3)]">
            <Shield size={28} className="text-white" />
          </div>
        </div>
        <h3 className="text-xl font-black text-white text-center uppercase tracking-widest mb-3">
          Login Successful
        </h3>
        <p className="text-gray-400 text-xs text-center leading-relaxed mb-8">
          Would you like TRACE to securely remember this trusted device for faster authentication?
        </p>
        <div className="flex flex-col gap-3">
          <button
            onClick={onSave}
            className="w-full bg-cyan-500 hover:bg-cyan-400 text-black py-4 rounded-2xl font-black text-xs uppercase tracking-widest transition-all shadow-[0_0_20px_rgba(34,211,238,0.3)] cursor-pointer"
          >
            Save Credentials
          </button>
          <button
            onClick={onSkip}
            className="w-full bg-white/5 hover:bg-white/10 border border-white/10 text-gray-400 hover:text-white py-4 rounded-2xl font-black text-xs uppercase tracking-widest transition-all cursor-pointer"
          >
            Not Now
          </button>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Forgot Access Key — 3-step flow
// ─────────────────────────────────────────────────────────────────────────────
function ForgotKeyFlow({ onBack }) {
  const [step, setStep] = useState(1); // 1=identifier, 2=otp, 3=new password
  const [identifier, setIdentifier] = useState("");
  const [otp, setOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [resetUsername, setResetUsername] = useState("");
  const [devOtp, setDevOtp] = useState(null); // dev mode OTP display
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const [showNewPw, setShowNewPw] = useState(false);
  const [showConfirmPw, setShowConfirmPw] = useState(false);

  const pwCriteria = getPasswordCriteria(newPassword);

  const handleRequestOtp = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await authApi.forgotPassword(identifier);
      if (res.success) {
        setDevOtp(res.dev_otp || null);
        setStep(2);
        setSuccess("Synchronization code dispatched. Check your registered email.");
      } else {
        setError(res.error || "Failed to initiate recovery");
      }
    } catch (err) {
      setError(err.message || err.response?.data?.error || err.response?.data?.message || "Network failure");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    if (otp.length !== 6) {
      setError("Enter the complete 6-digit code.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const res = await authApi.verifyOtp(identifier, otp);
      if (res.success) {
        setResetToken(res.reset_token);
        setResetUsername(res.username);
        setStep(3);
        setSuccess("");
        setDevOtp(null);
      } else {
        setError(res.error || "Invalid synchronization code");
      }
    } catch (err) {
      setError(err.message || err.response?.data?.error || err.response?.data?.message || "Network failure");
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    if (!allCriteriaMet(pwCriteria)) {
      setError("Access Key does not meet security requirements.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Access Keys do not match.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const res = await authApi.resetPassword(resetUsername, resetToken, newPassword);
      if (res.success) {
        setStep(4);
        setSuccess(res.message || "Access Key updated successfully.");
      } else {
        setError(res.error || "Reset failed");
      }
    } catch (err) {
      setError(err.message || err.response?.data?.error || err.response?.data?.message || "Network failure");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-in slide-in-from-right-4 duration-300">
      {/* Back button */}
      <button
        type="button"
        onClick={onBack}
        className="flex items-center gap-2 text-[10px] text-gray-500 hover:text-cyan-400 font-black uppercase tracking-widest transition-colors cursor-pointer"
      >
        <ChevronLeft size={14} /> Return to Login
      </button>

      <h2 className="text-xl font-black text-white uppercase tracking-widest italic text-center">
        {step < 4 ? "Access Key Recovery" : "Recovery Complete"}
      </h2>

      {/* Step indicators */}
      {step < 4 && (
        <div className="flex items-center justify-center gap-2 mb-2">
          {[1, 2, 3].map((s) => (
            <div key={s} className={`flex items-center gap-2 ${s < 3 ? "flex-1" : ""}`}>
              <div
                className={`w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-black transition-all ${
                  step > s
                    ? "bg-cyan-500 text-black"
                    : step === s
                    ? "border-2 border-cyan-500 text-cyan-400"
                    : "border border-gray-700 text-gray-600"
                }`}
              >
                {step > s ? <Check size={12} /> : s}
              </div>
              {s < 3 && <div className={`flex-1 h-px ${step > s ? "bg-cyan-500" : "bg-gray-800"}`} />}
            </div>
          ))}
        </div>
      )}

      {error && <ErrorBox message={error} />}
      {success && step !== 4 && <SuccessBox message={success} />}

      {/* Step 1: Enter Analyst ID or email */}
      {step === 1 && (
        <form onSubmit={handleRequestOtp} className="space-y-5">
          <CyberInput
            icon={User}
            label="Analyst ID or Registered Email"
            value={identifier}
            onChange={(e) => setIdentifier(e.target.value)}
            placeholder="USERNAME or email@domain.com"
            required
          />
          <SubmitButton loading={loading} label="Dispatch Recovery Code" loadingLabel="Dispatching..." />
        </form>
      )}

      {/* Step 2: Enter OTP */}
      {step === 2 && (
        <form onSubmit={handleVerifyOtp} className="space-y-5">
          <div>
            <label className="block text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-2">
              6-Digit Synchronization Code
            </label>
            <input
              type="text"
              value={otp}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="0  0  0  0  0  0"
              className="w-full bg-black/40 border-2 border-white/5 rounded-2xl px-6 py-5 text-white text-center text-3xl font-black tracking-[0.5em] focus:border-cyan-500 outline-none transition-all placeholder:text-gray-800"
              required
            />
          </div>
          {/* Dev mode OTP display */}
          {devOtp && (
            <div className="bg-yellow-500/10 border border-yellow-500/20 p-3 rounded-xl">
              <p className="text-[9px] text-yellow-400 font-black uppercase tracking-widest text-center">
                ⚠ DEV MODE — Your OTP: <span className="text-white text-sm tracking-[0.3em]">{devOtp}</span>
              </p>
              <p className="text-[8px] text-yellow-400/60 uppercase tracking-widest text-center mt-1">
                Remove this in production — send via email instead
              </p>
            </div>
          )}
          <SubmitButton loading={loading} label="Verify Code" loadingLabel="Verifying..." />
          <p
            onClick={() => { setStep(1); setOtp(""); setError(""); setSuccess(""); }}
            className="text-center text-[10px] text-gray-500 font-black uppercase cursor-pointer hover:text-white transition-colors"
          >
            Resend Code
          </p>
        </form>
      )}

      {/* Step 3: Set new password */}
      {step === 3 && (
        <form onSubmit={handleResetPassword} className="space-y-5">
          <div>
            <label className="block text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
              <KeyRound size={12} /> New Access Key
            </label>
            <div className="relative">
              <input
                type={showNewPw ? "text" : "password"}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-black/40 border border-white/10 rounded-2xl px-6 py-4 text-white focus:border-cyan-500 outline-none transition-all pl-12 pr-12"
                required
              />
              <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-600" size={18} />
              <button
                type="button"
                onClick={() => setShowNewPw(!showNewPw)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-600 hover:text-cyan-500 transition-colors cursor-pointer"
              >
                {showNewPw ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
              <KeyRound size={12} /> Confirm Access Key
            </label>
            <div className="relative">
              <input
                type={showConfirmPw ? "text" : "password"}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-black/40 border border-white/10 rounded-2xl px-6 py-4 text-white focus:border-cyan-500 outline-none transition-all pl-12 pr-12"
                required
              />
              <KeyRound className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-600" size={18} />
              <button
                type="button"
                onClick={() => setShowConfirmPw(!showConfirmPw)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-600 hover:text-cyan-500 transition-colors cursor-pointer"
              >
                {showConfirmPw ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </div>

          {/* Password strength */}
          <div className="bg-black/20 p-4 rounded-2xl border border-white/5 space-y-2">
            <p className="text-[10px] font-black text-gray-500 uppercase mb-2">Security Requirements</p>
            {[
              { label: "8+ Characters", met: pwCriteria.length },
              { label: "Uppercase Letter", met: pwCriteria.upper },
              { label: "Lowercase Letter", met: pwCriteria.lower },
              { label: "Number", met: pwCriteria.number },
              { label: "Special Character", met: pwCriteria.special },
            ].map((c, i) => (
              <div key={i} className="flex items-center justify-between">
                <span className="text-[10px] text-gray-400 font-bold">{c.label}</span>
                {c.met ? <Check size={14} className="text-green-500" /> : <X size={14} className="text-red-500/50" />}
              </div>
            ))}
          </div>

          <SubmitButton loading={loading} label="Update Access Key" loadingLabel="Updating..." />
        </form>
      )}

      {/* Step 4: Complete */}
      {step === 4 && (
        <div className="text-center space-y-6">
          <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto shadow-[0_0_25px_rgba(34,197,94,0.3)]">
            <Check size={32} className="text-green-400" />
          </div>
          <p className="text-gray-300 text-sm leading-relaxed">
            {success || "Access Key updated. All previous sessions have been terminated."}
          </p>
          <button
            onClick={onBack}
            className="w-full bg-cyan-500 hover:bg-cyan-400 text-black py-5 rounded-2xl font-black text-xs uppercase tracking-widest transition-all shadow-[0_0_20px_rgba(34,211,238,0.3)] cursor-pointer"
          >
            Return to Login Terminal
          </button>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Auth component
// ─────────────────────────────────────────────────────────────────────────────
export default function Auth({ onLogin }) {
  const [view, setView] = useState("login"); // login | register | mfa | forgot
  const [formData, setFormData] = useState({ username: "", password: "" });
  const [rememberDevice, setRememberDevice] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showRememberModal, setShowRememberModal] = useState(false);
  const [pendingLoginData, setPendingLoginData] = useState(null); // { username, token }

  const isLogin = view === "login";
  const isMFA   = view === "mfa";
  const isForgot = view === "forgot";
  const isRegisteredSuccess = view === "registered_success";

  const pwCriteria = getPasswordCriteria(formData.password);

  // ── Login / Register handler ───────────────────────────────────────────────
  const handleAuth = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      if (isLogin) {
        const res = await authApi.login({
          username: formData.username,
          password: formData.password,
          remember: rememberDevice,
        });
        if (res.success) {
          // Store token temporarily; show modal before finalising login
          setPendingLoginData({ username: res.username, token: res.token });
          setView("mfa");
        } else {
          const rawErr = res.error || "Invalid Analyst ID or Access Key.";
          setError(sanitizeAuthError(rawErr, "Invalid Analyst ID or Access Key."));
        }
      } else {
        // Register
        const res = await authApi.signup(formData);
        if (res.success) {
          setView("registered_success");
          setError("");
        } else {
          const rawErr = res.error || "Unable to create analyst account. Please try again.";
          setError(sanitizeAuthError(rawErr, "ACCOUNT CREATION FAILED: Unable to create analyst account. Please try again."));
        }
      }
    } catch (err) {
      // Lockout or network error
      const msg = err.message || err.response?.data?.error || err.response?.data?.message || "";
      const defaultErr = isLogin
        ? "Unable to connect to authentication server. Please try again."
        : "ACCOUNT CREATION FAILED: Unable to create analyst account. Please try again.";
      setError(sanitizeAuthError(msg, defaultErr));
    } finally {
      setIsLoading(false);
    }
  };

  // ── MFA handler ───────────────────────────────────────────────────────────
  const handleMFAVerify = (e) => {
    e.preventDefault();
    if (mfaCode.length !== 6) {
      setError("Enter the complete 6-digit synchronization key.");
      return;
    }
    // In production replace this with a real TOTP/server-verified MFA call
    if (mfaCode === "123456" || mfaCode.length === 6) {
      setError("");
      setShowRememberModal(true);
    } else {
      setError("Invalid Synchronization Key.");
    }
  };

  // ── Remember device handlers ──────────────────────────────────────────────
  const finaliseLogin = (remember) => {
    if (!pendingLoginData) return;
    storeToken(pendingLoginData.token, remember);
    storeUsername(pendingLoginData.username, remember);
    setShowRememberModal(false);
    onLogin(pendingLoginData.username, pendingLoginData.token, remember);
  };

  const handleSaveCredentials = () => finaliseLogin(true);
  const handleSkipRemember    = () => finaliseLogin(false);

  // ─────────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────────
  return (
    <>
      {showRememberModal && (
        <RememberDeviceModal onSave={handleSaveCredentials} onSkip={handleSkipRemember} />
      )}

      <div className="min-h-screen bg-[#06080e] flex items-center justify-center p-4 relative overflow-hidden font-sans">
        {/* Background glows */}
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-blue-600/10 rounded-full blur-[120px] pointer-events-none" />

        <div className="w-full max-w-md relative z-10">
          {/* Logo */}
          <div className="flex justify-center mb-8">
            <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-2xl flex items-center justify-center shadow-[0_0_30px_rgba(34,211,238,0.3)] rotate-3">
              <Shield size={32} className="text-white" />
            </div>
          </div>

          <div className="bg-[#0b1020]/80 backdrop-blur-xl border border-white/10 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
            <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:20px_20px] pointer-events-none" />

            {/* Title */}
            {!isForgot && !isRegisteredSuccess && (
              <h2 className="text-2xl font-black text-white text-center mb-8 uppercase tracking-widest italic">
                {isMFA
                  ? "MFA VERIFICATION"
                  : isLogin
                  ? "Neural Login"
                  : "Agent Enrollment"}
              </h2>
            )}

            {/* ── MFA Screen ───────────────────────────────────────────────── */}
            {isMFA && (
              <div className="space-y-6 animate-in slide-in-from-right-4 duration-500">
                <div className="text-center mb-6">
                  <p className="text-gray-500 text-[10px] font-black uppercase">
                    Enter your 6-digit Synchronization Key
                  </p>
                </div>
                <form onSubmit={handleMFAVerify} className="space-y-6 relative z-10">
                  <input
                    type="text"
                    placeholder="0  0  0  0  0  0"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    className="w-full bg-black/40 border-2 border-white/5 rounded-2xl px-6 py-5 text-white text-center text-3xl font-black tracking-[0.5em] focus:border-cyan-500 outline-none transition-all placeholder:text-gray-800"
                    required
                  />
                  <ErrorBox message={error} />
                  <button
                    type="submit"
                    className="w-full bg-cyan-500 hover:bg-cyan-400 text-black py-5 rounded-2xl font-black text-xs uppercase tracking-widest transition-all shadow-[0_0_20px_rgba(34,211,238,0.3)] cursor-pointer"
                  >
                    Sync Identity
                  </button>
                  <p
                    onClick={() => { setView("login"); setMfaCode(""); setError(""); }}
                    className="text-center text-[10px] text-gray-500 font-black uppercase cursor-pointer hover:text-white transition-colors"
                  >
                    Abort &amp; Return
                  </p>
                </form>
              </div>
            )}

            {/* ── Forgot Access Key Flow ───────────────────────────────────── */}
            {isForgot && (
              <ForgotKeyFlow onBack={() => { setView("login"); setError(""); }} />
            )}

            {/* ── Registered Success Screen ─────────────────────────────────── */}
            {isRegisteredSuccess && (
              <div className="space-y-6 animate-in slide-in-from-right-4 duration-500 text-center relative z-10">
                <div className="w-16 h-16 bg-cyan-500/20 border border-cyan-500/30 rounded-2xl flex items-center justify-center mx-auto shadow-[0_0_25px_rgba(34,211,238,0.3)]">
                  <Check size={32} className="text-cyan-400" />
                </div>
                <div className="space-y-2">
                  <h3 className="text-xl font-black text-white uppercase tracking-widest italic">
                    ANALYST ACCOUNT CREATED
                  </h3>
                  <p className="text-gray-400 text-xs leading-relaxed max-w-xs mx-auto">
                    Your analyst credentials have been registered successfully.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setView("login");
                    setFormData((prev) => ({ username: prev.username, password: "" }));
                    setError("");
                  }}
                  className="w-full bg-cyan-500 hover:bg-cyan-400 text-black py-5 rounded-2xl font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(34,211,238,0.3)] mt-6 cursor-pointer"
                >
                  PROCEED TO LOGIN →
                </button>
              </div>
            )}

            {/* ── Login / Register Form ───────────────────────────────────── */}
            {!isMFA && !isForgot && !isRegisteredSuccess && (
              <form onSubmit={handleAuth} className="relative z-10 space-y-5">

                {/* Analyst ID */}
                <div>
                  <label className="block text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
                    <User size={12} /> Analyst ID
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      value={formData.username}
                      onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                      className="w-full bg-black/40 border border-white/10 rounded-2xl px-6 py-4 text-white focus:border-cyan-500 outline-none transition-all pl-12"
                      placeholder="USERNAME"
                      required
                    />
                    <User className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-600" size={18} />
                  </div>
                </div>

                {/* Access Key */}
                <div>
                  <label className="block text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
                    <Lock size={12} /> Access Key
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={formData.password}
                      onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                      className="w-full bg-black/40 border border-white/10 rounded-2xl px-6 py-4 text-white focus:border-cyan-500 outline-none transition-all pl-12 pr-12"
                      placeholder="••••••••"
                      required
                    />
                    <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-600" size={18} />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-600 hover:text-cyan-500 transition-colors cursor-pointer"
                    >
                      {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>

                  {/* Forgot Access Key link — login mode only */}
                  {isLogin && (
                    <div className="text-right mt-2">
                      <button
                        type="button"
                        onClick={() => { setView("forgot"); setError(""); }}
                        className="text-[9px] text-gray-500 hover:text-cyan-400 font-black uppercase tracking-widest transition-colors cursor-pointer"
                      >
                        Forgot Access Key?
                      </button>
                    </div>
                  )}
                </div>

                {/* Remember this device — login mode only */}
                {isLogin && (
                  <label className="flex items-center gap-3 cursor-pointer group select-none">
                    <div
                      onClick={() => setRememberDevice(!rememberDevice)}
                      className={`w-5 h-5 rounded border flex items-center justify-center transition-all ${
                        rememberDevice
                          ? "bg-cyan-500 border-cyan-500"
                          : "border-gray-600 bg-black/30 group-hover:border-gray-400"
                      }`}
                    >
                      {rememberDevice && <Check size={12} className="text-black" />}
                    </div>
                    <span className="text-[10px] text-gray-400 font-black uppercase tracking-widest group-hover:text-gray-300 transition-colors">
                      Remember this device
                    </span>
                  </label>
                )}

                {/* Password strength — register mode */}
                {!isLogin && (
                  <div className="bg-black/20 p-4 rounded-2xl border border-white/5 space-y-3">
                    <p className="text-[10px] font-black text-gray-500 uppercase mb-2">Neural Security Metrics</p>
                    {[
                      { label: "8+ Char Link",       met: pwCriteria.length },
                      { label: "Upper Register",      met: pwCriteria.upper },
                      { label: "Binary Data (Num)",   met: pwCriteria.number },
                      { label: "Special Protocol",    met: pwCriteria.special },
                    ].map((c, i) => (
                      <div key={i} className="flex items-center justify-between">
                        <span className="text-[10px] text-gray-400 font-bold">{c.label}</span>
                        {c.met ? (
                          <Check size={14} className="text-green-500" />
                        ) : (
                          <X size={14} className="text-red-500/50" />
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Error display */}
                <ErrorBox message={error} />

                {/* Submit */}
                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black py-5 rounded-2xl font-black text-xs uppercase tracking-[0.2em] transition-all flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(34,211,238,0.3)] mt-8 cursor-pointer"
                >
                  {isLoading
                    ? isLogin
                      ? "LOGGING IN..."
                      : "CREATING ACCOUNT..."
                    : isLogin
                    ? "INITIATE LOGIN"
                    : "CREATE ANALYST ACCOUNT →"}
                  {!isLoading && <ArrowRight size={16} />}
                </button>

                {/* Toggle login / register */}
                <p className="text-center text-[10px] text-gray-500 font-bold uppercase tracking-widest">
                  {isLogin ? "No Clearance?" : "Clearance Granted?"}{" "}
                  <button
                    type="button"
                    onClick={() => { setView(isLogin ? "register" : "login"); setError(""); }}
                    className="text-cyan-400 hover:text-cyan-300 ml-1 font-black cursor-pointer"
                  >
                    {isLogin ? "Register Analyst" : "Login Terminal"}
                  </button>
                </p>
              </form>
            )}
          </div>

          {/* Footer badges */}
          <div className="mt-12 flex justify-center gap-8">
            <div className="text-center">
              <p className="text-white font-black text-xs tracking-tighter">AES-256</p>
              <p className="text-[8px] text-gray-600 font-black uppercase tracking-widest mt-1">Encryption</p>
            </div>
            <div className="text-center">
              <p className="text-white font-black text-xs tracking-tighter">ISO-27001</p>
              <p className="text-[8px] text-gray-600 font-black uppercase tracking-widest mt-1">Compliance</p>
            </div>
            <div className="text-center">
              <p className="text-white font-black text-xs tracking-tighter">TRACE-L5</p>
              <p className="text-[8px] text-gray-600 font-black uppercase tracking-widest mt-1">Protocol</p>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
