import { render, screen } from "@testing-library/react";
import { HashDisplay } from "./HashDisplay";
import { IntegrityBadge } from "./IntegrityBadge";
import { SeverityBadge } from "./SeverityBadge";
import { ProvenanceTag } from "./ProvenanceTag";
import { Timestamp } from "./Timestamp";
import { EmptyState } from "./EmptyState";
import { ErrorState } from "./ErrorState";
import { ApiError } from "../../lib/types";

describe("HashDisplay", () => {
  it("truncates long hashes and exposes the full value", () => {
    const hash = "a".repeat(64);
    render(<HashDisplay value={hash} />);
    expect(screen.getByTitle(`SHA-256: ${hash}`)).toBeInTheDocument();
    expect(screen.getByText(/…/)).toBeInTheDocument();
  });
});

describe("IntegrityBadge", () => {
  it("distinguishes plaintext mismatch from storage authentication failure", () => {
    const { rerender } = render(<IntegrityBadge status="hash_mismatch" />);
    expect(screen.getByText("Hash mismatch")).toHaveAttribute(
      "title",
      expect.stringContaining("plaintext"),
    );
    rerender(<IntegrityBadge status="decryption_failed" />);
    expect(screen.getByText("Storage auth failed")).toHaveAttribute(
      "title",
      expect.stringContaining("AES-GCM"),
    );
  });
});

describe("SeverityBadge", () => {
  it("renders severity without using it as decoration copy", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });
});

describe("ProvenanceTag", () => {
  it("labels LLM output as assisted rather than observed fact", () => {
    render(<ProvenanceTag provenance="llm_assisted" />);
    expect(screen.getByText("LLM assisted")).toHaveAttribute(
      "title",
      expect.stringContaining("cannot write forensic facts"),
    );
  });
});

describe("Timestamp", () => {
  it("renders an absolute timezone-aware time", () => {
    render(<Timestamp value="2026-01-15T10:30:00Z" />);
    expect(screen.getByRole("time")).toHaveAttribute("dateTime", "2026-01-15T10:30:00.000Z");
    expect(screen.getByRole("time")).toHaveTextContent("UTC");
  });
});

describe("EmptyState and ErrorState", () => {
  it("renders an empty explanation", () => {
    render(<EmptyState title="None" body="Nothing in scope." />);
    expect(screen.getByText("Nothing in scope.")).toBeInTheDocument();
  });

  it("surfaces API error codes as investigator-readable text", () => {
    render(<ErrorState error={new ApiError(403, "permission_denied", "Missing evidence:download")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Missing evidence:download");
  });
});
