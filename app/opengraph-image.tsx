import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Cloud IDS – Intrusion Detection System";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OgImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "1200px",
          height: "630px",
          background: "linear-gradient(135deg, #0f1923 0%, #1a2a38 50%, #0f1923 100%)",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          padding: "72px 80px",
          fontFamily: "sans-serif",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Background grid lines */}
        <div
          style={{
            position: "absolute",
            inset: 0,
            backgroundImage:
              "linear-gradient(rgba(25,133,161,0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(25,133,161,0.07) 1px, transparent 1px)",
            backgroundSize: "60px 60px",
          }}
        />

        {/* Glow blob */}
        <div
          style={{
            position: "absolute",
            top: "-80px",
            right: "-80px",
            width: "480px",
            height: "480px",
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(25,133,161,0.18) 0%, transparent 70%)",
          }}
        />

        {/* Shield icon */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            width: "72px",
            height: "72px",
            borderRadius: "16px",
            background: "#1985a1",
            marginBottom: "28px",
          }}
        >
          <svg width="40" height="40" viewBox="0 0 32 32" fill="none">
            <path
              d="M16 2L4 7v9c0 7 5.5 12.5 12 14 6.5-1.5 12-7 12-14V7L16 2Z"
              fill="white"
              opacity="0.9"
            />
            <circle cx="16" cy="16" r="5.5" stroke="#1985a1" strokeWidth="1.4" fill="none" />
            <circle cx="16" cy="16" r="2.5" fill="#1985a1" />
            <line x1="16" y1="16" x2="20.5" y2="11.5" stroke="#1985a1" strokeWidth="1.4" strokeLinecap="round" />
          </svg>
        </div>

        {/* Title */}
        <div
          style={{
            fontSize: "58px",
            fontWeight: "800",
            color: "#f0f4f8",
            lineHeight: 1.1,
            letterSpacing: "-1px",
            marginBottom: "16px",
          }}
        >
          Cloud IDS
        </div>

        {/* Subtitle */}
        <div
          style={{
            fontSize: "26px",
            fontWeight: "400",
            color: "#1985a1",
            marginBottom: "32px",
            letterSpacing: "0.5px",
          }}
        >
          Intrusion Detection System for AWS CloudTrail
        </div>

        {/* Rule pills */}
        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginBottom: "40px" }}>
          {[
            "Root Account",
            "IAM Escalation",
            "CloudTrail Disabled",
            "Bulk S3 Download",
            "Mass Deletion",
            "Access Denied Spike",
          ].map((tag) => (
            <div
              key={tag}
              style={{
                background: "rgba(25,133,161,0.15)",
                border: "1px solid rgba(25,133,161,0.35)",
                borderRadius: "999px",
                padding: "6px 16px",
                fontSize: "15px",
                color: "#7ecfdf",
                fontWeight: "500",
              }}
            >
              {tag}
            </div>
          ))}
        </div>

        {/* Footer */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "12px",
            borderTop: "1px solid rgba(25,133,161,0.2)",
            paddingTop: "24px",
          }}
        >
          <div style={{ fontSize: "15px", color: "#4c5c68", fontWeight: "600" }}>
            Group 46
          </div>
          <div style={{ width: "4px", height: "4px", borderRadius: "50%", background: "#4c5c68" }} />
          <div style={{ fontSize: "15px", color: "#4c5c68" }}>Riya Karagwal &amp; Rhea T. Chakraborty</div>
          <div style={{ width: "4px", height: "4px", borderRadius: "50%", background: "#4c5c68" }} />
          <div style={{ fontSize: "15px", color: "#4c5c68" }}>Amity University</div>
        </div>
      </div>
    ),
    { ...size }
  );
}
