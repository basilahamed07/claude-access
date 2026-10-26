import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { StaticReplay } from "./features/sessions/StaticReplay";
import "./theme/global.css";
import { applyTheme, readTheme } from "./theme/ThemeToggle";

applyTheme(readTheme());
createRoot(document.getElementById("root")!).render(<StrictMode><StaticReplay /></StrictMode>);
