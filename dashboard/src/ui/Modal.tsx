import * as Dialog from "@radix-ui/react-dialog";
import type { ReactNode } from "react";

/** A centred dialog. Rendered through Radix so it stacks correctly over an open drawer. */
export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  return (
    <Dialog.Root open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="scrim" style={{ zIndex: 30 }} />
        <Dialog.Content className="dialog" aria-describedby={undefined}>
          <Dialog.Title asChild><h2>{title}</h2></Dialog.Title>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
