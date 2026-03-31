import { useNavigate } from "react-router-dom";

export default function Sensensus() {
  const navigate = useNavigate();

  return (
    <div style={{ height: "100vh", width: "100%" }}>
      <button
        onClick={() => navigate("/")}
        style={{
          position: "absolute",
          top: 20,
          left: 20,
          zIndex: 10
        }}
      >
        ← Dashboard
      </button>

      <iframe
        src="/sensensus.html"
        style={{
          width: "100%",
          height: "100%",
          border: "none"
        }}
      />
    </div>
  );
}