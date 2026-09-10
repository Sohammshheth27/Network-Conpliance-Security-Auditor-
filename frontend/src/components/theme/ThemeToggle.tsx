import { Moon, Sun, Monitor } from "lucide-react";
import { useTheme } from "./ThemeProvider";

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <div className="flex items-center gap-1 p-1 bg-background border border-border rounded-lg">
      <button
        onClick={() => setTheme("light")}
        className={`p-1.5 rounded-md flex items-center justify-center transition-colors ${
          theme === "light" 
            ? "bg-secondary text-foreground shadow-sm" 
            : "text-muted hover:text-foreground hover:bg-secondary/50"
        }`}
        title="Light Mode"
      >
        <Sun className="w-4 h-4" />
      </button>
      <button
        onClick={() => setTheme("dark")}
        className={`p-1.5 rounded-md flex items-center justify-center transition-colors ${
          theme === "dark" 
            ? "bg-secondary text-foreground shadow-sm" 
            : "text-muted hover:text-foreground hover:bg-secondary/50"
        }`}
        title="Dark Mode"
      >
        <Moon className="w-4 h-4" />
      </button>
      <button
        onClick={() => setTheme("system")}
        className={`p-1.5 rounded-md flex items-center justify-center transition-colors ${
          theme === "system" 
            ? "bg-secondary text-foreground shadow-sm" 
            : "text-muted hover:text-foreground hover:bg-secondary/50"
        }`}
        title="System Preference"
      >
        <Monitor className="w-4 h-4" />
      </button>
    </div>
  );
}
