import * as Dialog from "@radix-ui/react-dialog";
import type { ReactNode } from "react";

export function Drawer({ open, onClose, title, children, wide = false }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean }) {
  return (
    <Dialog.Root open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="scrim" />
        <Dialog.Content className={`drawer${wide ? " wide" : ""}`} aria-describedby={undefined}>
          <div className="row between">
            <Dialog.Title asChild><h2>{title}</h2></Dialog.Title>
            <Dialog.Close className="btn quiet" aria-label="Close">Close</Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
