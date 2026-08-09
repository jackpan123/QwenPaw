import React, { createRef } from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAuthorizationStore } from "@/stores/authorizationStore";
import WhisperSpeechButton, { type WhisperSpeechButtonRef } from "./index";

const { mockGetUserMedia, mockTranscribeAudio, mockTrackStop, capturedClick } =
  vi.hoisted(() => ({
    mockGetUserMedia: vi.fn(),
    mockTranscribeAudio: vi.fn(),
    mockTrackStop: vi.fn(),
    capturedClick: { current: undefined as (() => void) | undefined },
  }));

vi.mock("@/api/modules/agent", () => ({
  agentApi: { transcribeAudio: mockTranscribeAudio },
  TranscriptionError: class TranscriptionError extends Error {
    code = "TRANSCRIPTION_FAILED";
  },
}));

vi.mock("@agentscope-ai/design", () => ({
  IconButton: ({
    onClick,
    disabled,
  }: {
    onClick?: () => void;
    disabled?: boolean;
  }) => {
    capturedClick.current = onClick;
    return (
      <button data-testid="voice-button" onClick={onClick} disabled={disabled}>
        voice
      </button>
    );
  },
}));

vi.mock("@agentscope-ai/icons", () => ({
  SparkMicLine: () => <span>mic</span>,
}));

vi.mock("antd", () => ({
  Tooltip: ({ children }: { children: React.ReactNode }) => children,
  message: { error: vi.fn(), warning: vi.fn() },
}));

vi.mock("@ant-design/icons", () => ({
  LoadingOutlined: () => <span>loading</span>,
}));

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

const mockStream = {
  getTracks: () => [{ stop: mockTrackStop }],
} as unknown as MediaStream;

class FakeMediaRecorder {
  static instances: FakeMediaRecorder[] = [];
  static isTypeSupported = vi.fn(() => true);

  ondataavailable: ((event: BlobEvent) => void) | null = null;
  onstop: ((event: Event) => void | Promise<void>) | null = null;
  state: RecordingState = "inactive";
  readonly stream: MediaStream;
  readonly mimeType: string;
  stopPromise: Promise<void> = Promise.resolve();

  start = vi.fn(() => {
    this.state = "recording";
  });

  stop = vi.fn(() => {
    this.state = "inactive";
    this.stopPromise = Promise.resolve(this.onstop?.(new Event("stop"))).then(
      () => undefined,
    );
  });

  constructor(stream: MediaStream, options?: MediaRecorderOptions) {
    this.stream = stream;
    this.mimeType = options?.mimeType ?? "";
    FakeMediaRecorder.instances.push(this);
  }

  emitData(data: Blob) {
    this.ondataavailable?.({ data } as BlobEvent);
  }

  async emitStop() {
    await this.onstop?.(new Event("stop"));
  }
}

function setCanMutate(canMutate: boolean) {
  useAuthorizationStore.getState().set({
    authEnabled: true,
    username: canMutate ? "admin-user" : "member-user",
    roles: [canMutate ? "admin" : "member"],
    canMutate,
  });
}

function renderButton() {
  const ref = createRef<WhisperSpeechButtonRef>();
  const onTranscription = vi.fn();
  const view = render(
    <WhisperSpeechButton ref={ref} onTranscription={onTranscription} />,
  );
  return { ...view, ref, onTranscription };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}

async function invoke(callback: (() => void) | undefined) {
  await act(async () => {
    callback?.();
    await Promise.resolve();
  });
}

describe("WhisperSpeechButton authorization", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    FakeMediaRecorder.instances = [];
    capturedClick.current = undefined;
    setCanMutate(false);
    mockGetUserMedia.mockResolvedValue(mockStream);
    mockTranscribeAudio.mockResolvedValue({ text: "transcribed text" });
    Object.defineProperty(navigator, "mediaDevices", {
      configurable: true,
      value: { getUserMedia: mockGetUserMedia },
    });
    Object.defineProperty(globalThis, "MediaRecorder", {
      configurable: true,
      value: FakeMediaRecorder,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("blocks direct toggle and click attempts for a read-only member", async () => {
    const { ref } = renderButton();

    await invoke(() => ref.current?.toggleRecording());
    await invoke(capturedClick.current);

    expect(screen.getByTestId("voice-button")).toBeInTheDocument();
    expect(mockGetUserMedia).not.toHaveBeenCalled();
    expect(FakeMediaRecorder.instances).toHaveLength(0);
  });

  it("keeps a captured admin handler inert after runtime downgrade", async () => {
    setCanMutate(true);
    const { ref } = renderButton();
    const staleClick = capturedClick.current;
    const staleToggle = ref.current?.toggleRecording;
    setCanMutate(false);

    await invoke(staleClick);
    await invoke(staleToggle);

    expect(mockGetUserMedia).not.toHaveBeenCalled();
    expect(FakeMediaRecorder.instances).toHaveLength(0);
  });

  it("cleans up without uploading when permission is revoked during recording", async () => {
    setCanMutate(true);
    const { ref, onTranscription } = renderButton();
    await invoke(() => ref.current?.toggleRecording());
    const recorder = FakeMediaRecorder.instances[0];
    recorder.emitData(new Blob(["voice"], { type: "audio/webm" }));
    setCanMutate(false);

    await act(async () => recorder.emitStop());

    expect(mockTrackStop).toHaveBeenCalledOnce();
    expect(mockTranscribeAudio).not.toHaveBeenCalled();
    expect(onTranscription).not.toHaveBeenCalled();
    expect(ref.current?.isRecording()).toBe(false);
    expect(ref.current?.isLoading()).toBe(false);
  });

  it("transcribes and cleans up when permission remains allowed", async () => {
    setCanMutate(true);
    const { ref, onTranscription } = renderButton();
    await invoke(() => ref.current?.toggleRecording());
    const recorder = FakeMediaRecorder.instances[0];
    recorder.emitData(new Blob(["voice"], { type: "audio/webm" }));

    await act(async () => recorder.emitStop());

    await waitFor(() =>
      expect(mockTranscribeAudio).toHaveBeenCalledWith(expect.any(Blob)),
    );
    const uploadedBlob = mockTranscribeAudio.mock.calls[0][0] as Blob;
    expect(uploadedBlob.size).toBeGreaterThan(0);
    expect(onTranscription).toHaveBeenCalledWith("transcribed text");
    expect(mockTrackStop).toHaveBeenCalledOnce();
    expect(ref.current?.isRecording()).toBe(false);
    expect(ref.current?.isLoading()).toBe(false);
  });

  it("stops an active recording on unmount without uploading", async () => {
    setCanMutate(true);
    const clearTimeoutSpy = vi.spyOn(globalThis, "clearTimeout");
    const { ref, onTranscription, unmount } = renderButton();
    await invoke(() => ref.current?.toggleRecording());
    const recorder = FakeMediaRecorder.instances[0];
    recorder.emitData(new Blob(["voice"], { type: "audio/webm" }));

    unmount();
    await act(async () => recorder.stopPromise);

    expect(recorder.stop).toHaveBeenCalledOnce();
    expect(mockTrackStop).toHaveBeenCalledOnce();
    expect(clearTimeoutSpy).toHaveBeenCalled();
    expect(mockTranscribeAudio).not.toHaveBeenCalled();
    expect(onTranscription).not.toHaveBeenCalled();
  });

  it("discards a pending media stream that resolves after unmount", async () => {
    setCanMutate(true);
    const pendingStream = deferred<MediaStream>();
    mockGetUserMedia.mockReturnValue(pendingStream.promise);
    const { ref, onTranscription, unmount } = renderButton();

    await invoke(() => ref.current?.toggleRecording());
    unmount();
    await act(async () => {
      pendingStream.resolve(mockStream);
      await pendingStream.promise;
      await Promise.resolve();
    });

    expect(mockTrackStop).toHaveBeenCalledOnce();
    expect(FakeMediaRecorder.instances).toHaveLength(0);
    expect(mockTranscribeAudio).not.toHaveBeenCalled();
    expect(onTranscription).not.toHaveBeenCalled();
  });

  it("discards a pending media stream after runtime downgrade", async () => {
    setCanMutate(true);
    const pendingStream = deferred<MediaStream>();
    mockGetUserMedia.mockReturnValue(pendingStream.promise);
    const { ref, onTranscription } = renderButton();

    await invoke(() => ref.current?.toggleRecording());
    setCanMutate(false);
    await act(async () => {
      pendingStream.resolve(mockStream);
      await pendingStream.promise;
      await Promise.resolve();
    });

    expect(mockTrackStop).toHaveBeenCalledOnce();
    expect(FakeMediaRecorder.instances).toHaveLength(0);
    expect(mockTranscribeAudio).not.toHaveBeenCalled();
    expect(onTranscription).not.toHaveBeenCalled();
  });
});
