import { create } from "zustand";

type UiState = {
  density: "comfortable" | "compact";
  railCollapsed: boolean;
  commandOpen: boolean;
  toggleDensity: () => void;
  toggleRail: () => void;
  setCommandOpen: (open: boolean) => void;
};

export const useUi = create<UiState>((set) => ({
  density: "comfortable",
  railCollapsed: false,
  commandOpen: false,
  toggleDensity: () =>
    set((state) => ({ density: state.density === "comfortable" ? "compact" : "comfortable" })),
  toggleRail: () => set((state) => ({ railCollapsed: !state.railCollapsed })),
  setCommandOpen: (open) => set({ commandOpen: open }),
}));
