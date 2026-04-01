import { BrowserRouter, Routes, Route } from "react-router-dom";
import App from "./App.jsx";
import Sensensus from "./pages/Sensensus.jsx";
import ReactDOM from "react-dom/client";

ReactDOM.createRoot(document.getElementById("root")).render(
  <BrowserRouter>
    <Routes>
      <Route path="/" element={<App />} />
      <Route path="/sensensus" element={<Sensensus />} />
    </Routes>
  </BrowserRouter>
);