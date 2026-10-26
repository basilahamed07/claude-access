import * as Dialog from "@radix-ui/react-dialog";
import { useState, type ReactNode } from "react";

/** Irreversible or loosening actions: the user must type the exact word first. */
export function ConfirmTyped({ open, onClose, onConfirm, title, phrase, action, busy, children }: {
  open: boolean; onClose: () => void; onConfirm: () => void; title: string; phrase: string; action: string; busy?: boolean; children?: ReactNode;
}) {
  const [typed, setTyped] = useState("");
  const ok = typed === phrase;
  return (
    <Dialog.Root open={open} onOpenChange={(o) => { if (!o) { setTyped(""); onClose(); } }}>
      <Dialog.Portal>
        <Dialog.Overlay className="scrim" style={{ zIndex: 30 }} />
        <Dialog.Content className="dialog" aria-describedby={undefined}>
          <Dialog.Title asChild><h2>{title}</h2></Dialog.Title>
          {children}
          <div className="field">
            <label htmlFor="confirm-typed">Type <code>{phrase}</code> to confirm</label>
            <input id="confirm-typed" type="text" autoComplete="off" value={typed} onChange={(e) => setTyped(e.target.value)} />
          </div>
          <div className="row">
            <button className="btn danger primary" disabled={!ok || busy} onClick={() => { onConfirm(); setTyped(""); }}>{action}</button>
            <Dialog.Close className="btn quiet" onClick={() => setTyped("")}>Cancel</Dialog.Close>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
