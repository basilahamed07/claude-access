import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app/router";
import "./theme/global.css";
import { applyTheme, readTheme } from "./theme/ThemeToggle";

applyTheme(readTheme());
createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
