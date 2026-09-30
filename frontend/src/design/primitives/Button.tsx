import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";

const styles: Record<Variant, string> = {
  primary: "bg-accent text-canvas hover:bg-teal-300",
  secondary: "bg-raised text-ink border border-line hover:bg-overlay",
  ghost: "text-muted hover:text-ink hover:bg-raised",
  danger: "bg-status-critical/15 text-status-critical border border-status-critical/30 hover:bg-status-critical/25",
};

export function Button({
  variant = "secondary",
  children,
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; children: ReactNode }) {
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium disabled:opacity-50 ${styles[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
