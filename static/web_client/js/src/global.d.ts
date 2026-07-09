import type { CamelliaConfig } from './core/config';

declare global {
  interface FileSystemEntry {
    readonly isFile: boolean;
    readonly isDirectory: boolean;
    readonly name: string;
    readonly fullPath: string;
  }

  interface FileSystemFileEntry extends FileSystemEntry {
    file(
      successCallback: (file: File) => void,
      errorCallback?: (error: DOMException) => void
    ): void;
  }

  interface FileSystemDirectoryEntry extends FileSystemEntry {
    createReader(): FileSystemDirectoryReader;
  }

  interface FileSystemDirectoryReader {
    readEntries(
      successCallback: (entries: FileSystemEntry[]) => void,
      errorCallback?: (error: DOMException) => void
    ): void;
  }

  interface Window {
    __CAMELLIA_WEB__?: CamelliaConfig;
    __CAMELLIA_WEB_BRIDGE__?: Record<string, unknown>;
    setByName?: (name: string, arg0?: unknown, arg1?: unknown) => string | void;
    getByName?: (name: string, arg0?: unknown) => string;
    init?: () => void;
    isMobile?: () => boolean;
    onInitFinished?: () => void;
    onGlobalEvent?: (payload: string) => void;
    onRegisteredEvent?: (payload: string) => void;
    onFullscreenChanged?: (value: boolean) => void;
    onRgba?: (
      display: number,
      rgba: Uint8Array,
      width?: number,
      height?: number
    ) => void;
    onVideoFrame?: (display: number, width?: number, height?: number) => void;
    onLoadAbFinished?: (payload: string) => void;
    onLoadGroupFinished?: (payload: string) => void;
    dialog?: (type: string, title: string, text: string) => void;
    loginDialog?: () => void;
    closeConnection?: () => void;
  }
}

export {};
