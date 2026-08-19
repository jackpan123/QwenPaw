import React, {
  useCallback,
  useEffect,
  useRef,
  useState,
  forwardRef,
  useImperativeHandle,
} from "react";
import { IconButton } from "@agentscope-ai/design";
import { SparkMicLine } from "@agentscope-ai/icons";
import { Tooltip, message } from "antd";
import { LoadingOutlined } from "@ant-design/icons";
import { useTranslation } from "react-i18next";
import { agentApi, TranscriptionError } from "@/api/modules/agent";
import { useUploadLimitStore } from "@/stores/uploadLimitStore";
import { useAuthorizationStore } from "@/stores/authorizationStore";

const MAX_RECORDING_DURATION_MS = 5 * 60 * 1000; // 5 minutes

export interface WhisperSpeechButtonRef {
  toggleRecording: () => void;
  isRecording: () => boolean;
  isLoading: () => boolean;
}

interface WhisperSpeechButtonProps {
  disabled?: boolean;
  onTranscription: (text: string) => void;
}

// Original recording icon animation from @agentscope-ai/chat
const SIZE = 1000;
const COUNT = 4;
const RECT_WIDTH = 140;
const RECT_RADIUS = RECT_WIDTH / 2;
const RECT_HEIGHT_MIN = 250;
const RECT_HEIGHT_MAX = 500;
const DURATION = 0.8;

const RecordingIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg
    viewBox={`0 0 ${SIZE} ${SIZE}`}
    xmlns="http://www.w3.org/2000/svg"
    className={className}
    style={{
      color: "#1890ff",
      height: "1.2em",
      width: "1.2em",
      verticalAlign: "top",
    }}
  >
    <title>Speech Recording</title>
    {Array.from({ length: COUNT }).map((_, index) => {
      const dest = (SIZE - RECT_WIDTH * COUNT) / (COUNT - 1);
      const x = index * (dest + RECT_WIDTH);
      const yMin = SIZE / 2 - RECT_HEIGHT_MIN / 2;
      const yMax = SIZE / 2 - RECT_HEIGHT_MAX / 2;

      return (
        <rect
          fill="currentColor"
          rx={RECT_RADIUS}
          ry={RECT_RADIUS}
          height={RECT_HEIGHT_MIN}
          width={RECT_WIDTH}
          x={x}
          y={yMin}
          key={index}
        >
          <animate
            attributeName="height"
            values={`${RECT_HEIGHT_MIN}; ${RECT_HEIGHT_MAX}; ${RECT_HEIGHT_MIN}`}
            keyTimes="0; 0.5; 1"
            dur={`${DURATION}s`}
            begin={`${(DURATION / COUNT) * index}s`}
            repeatCount="indefinite"
          />
          <animate
            attributeName="y"
            values={`${yMin}; ${yMax}; ${yMin}`}
            keyTimes="0; 0.5; 1"
            dur={`${DURATION}s`}
            begin={`${(DURATION / COUNT) * index}s`}
            repeatCount="indefinite"
          />
        </rect>
      );
    })}
  </svg>
);

const WhisperSpeechButton = forwardRef<
  WhisperSpeechButtonRef,
  WhisperSpeechButtonProps
>(({ disabled, onTranscription }, ref) => {
  const { t } = useTranslation();
  const [recording, setRecording] = useState(false);
  const [loading, setLoading] = useState(false);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const internalRecordingRef = useRef(false);
  const recordingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const releaseStreamRef = useRef<(() => void) | null>(null);
  const mountedRef = useRef(true);
  const suppressTranscriptionRef = useRef(false);

  const stopRecording = useCallback(() => {
    if (mediaRecorderRef.current && internalRecordingRef.current) {
      mediaRecorderRef.current.stop();
      internalRecordingRef.current = false;
      if (mountedRef.current) setRecording(false);
    }
  }, []);

  const startRecording = useCallback(async () => {
    if (
      !useAuthorizationStore.getState().canMutate ||
      internalRecordingRef.current ||
      loading
    ) {
      return;
    }
    suppressTranscriptionRef.current = false;
    let stream: MediaStream | null = null;
    let releaseStream: (() => void) | null = null;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      let streamReleased = false;
      releaseStream = () => {
        if (streamReleased) return;
        streamReleased = true;
        stream?.getTracks().forEach((track) => track.stop());
      };
      if (!mountedRef.current || !useAuthorizationStore.getState().canMutate) {
        releaseStream();
        return;
      }
      const mimeType = MediaRecorder.isTypeSupported("audio/webm")
        ? "audio/webm"
        : "audio/mp4";
      const recorder = new MediaRecorder(stream, { mimeType });
      chunksRef.current = [];

      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) {
          chunksRef.current.push(e.data);
        }
      };

      recorder.onstop = async () => {
        const recordedChunks = chunksRef.current;
        releaseStream?.();
        if (releaseStreamRef.current === releaseStream) {
          releaseStreamRef.current = null;
        }
        if (recordingTimerRef.current) {
          clearTimeout(recordingTimerRef.current);
          recordingTimerRef.current = null;
        }
        internalRecordingRef.current = false;
        mediaRecorderRef.current = null;
        chunksRef.current = [];
        if (mountedRef.current) setRecording(false);
        if (
          !mountedRef.current ||
          suppressTranscriptionRef.current ||
          !useAuthorizationStore.getState().canMutate
        ) {
          return;
        }

        const blob = new Blob(recordedChunks, { type: mimeType });

        // File size validation
        const sizeMb = blob.size / 1024 / 1024;
        const uploadLimit = useUploadLimitStore.getState().uploadMaxSizeMb;
        if (uploadLimit !== null && sizeMb > uploadLimit) {
          message.error(
            t("chat.speech.fileTooLarge", {
              size: sizeMb.toFixed(1),
              limit: uploadLimit,
            }),
          );
          return;
        }

        if (!mountedRef.current) return;
        setLoading(true);
        try {
          if (
            !mountedRef.current ||
            suppressTranscriptionRef.current ||
            !useAuthorizationStore.getState().canMutate
          ) {
            return;
          }
          const result = await agentApi.transcribeAudio(blob);
          if (
            result.text &&
            mountedRef.current &&
            !suppressTranscriptionRef.current &&
            useAuthorizationStore.getState().canMutate
          ) {
            onTranscription(result.text);
          }
        } catch (err) {
          if (
            !mountedRef.current ||
            suppressTranscriptionRef.current ||
            !useAuthorizationStore.getState().canMutate
          ) {
            return;
          }
          if (err instanceof TranscriptionError) {
            switch (err.code) {
              case "TRANSCRIPTION_DISABLED":
                message.warning(t("chat.speech.transcriptionDisabled"));
                break;
              case "FILE_TOO_LARGE":
                message.error(
                  t("chat.speech.fileTooLarge", {
                    size: sizeMb.toFixed(1),
                    limit: uploadLimit ?? "?",
                  }),
                );
                break;
              default:
                message.error(t("chat.speech.transcriptionFailed"));
            }
          } else {
            message.error(t("chat.speech.transcriptionFailed"));
          }
          console.error("Transcription error:", err);
        } finally {
          if (mountedRef.current) setLoading(false);
        }
      };

      recorder.start();
      mediaRecorderRef.current = recorder;
      releaseStreamRef.current = releaseStream;
      internalRecordingRef.current = true;
      if (mountedRef.current) setRecording(true);

      // Auto-stop after max duration
      recordingTimerRef.current = setTimeout(() => {
        if (internalRecordingRef.current) {
          message.warning(
            t("chat.speech.recordingTooLong", {
              limit: MAX_RECORDING_DURATION_MS / 1000,
            }),
          );
          stopRecording();
        }
      }, MAX_RECORDING_DURATION_MS);
    } catch (err) {
      releaseStream?.();
      if (!mountedRef.current) return;
      console.error("Microphone access error:", err);
      message.error(t("chat.speech.microphoneError"));
    }
  }, [onTranscription, t, loading, stopRecording]);

  const toggleRecording = useCallback(() => {
    if (loading) return;
    if (!useAuthorizationStore.getState().canMutate) {
      if (internalRecordingRef.current) {
        suppressTranscriptionRef.current = true;
        stopRecording();
      }
      return;
    }
    if (internalRecordingRef.current) {
      stopRecording();
    } else {
      startRecording();
    }
  }, [loading, startRecording, stopRecording]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      suppressTranscriptionRef.current = true;
      if (recordingTimerRef.current) {
        clearTimeout(recordingTimerRef.current);
        recordingTimerRef.current = null;
      }
      const recorder = mediaRecorderRef.current;
      if (recorder && internalRecordingRef.current) {
        try {
          recorder.stop();
        } finally {
          releaseStreamRef.current?.();
        }
      }
      internalRecordingRef.current = false;
      mediaRecorderRef.current = null;
      releaseStreamRef.current = null;
      chunksRef.current = [];
    };
  }, []);

  // Expose methods via ref
  useImperativeHandle(
    ref,
    () => ({
      toggleRecording,
      isRecording: () => internalRecordingRef.current,
      isLoading: () => loading,
    }),
    [toggleRecording, loading],
  );

  const isDisabled = disabled || loading;

  return (
    <Tooltip
      title={
        loading
          ? t("chat.speech.transcribing")
          : recording
          ? t("chat.speech.stopRecording")
          : t("chat.speech.startRecording")
      }
      mouseEnterDelay={0.5}
    >
      <IconButton
        bordered={false}
        icon={
          loading ? (
            <LoadingOutlined style={{ fontSize: "1.2em" }} />
          ) : recording ? (
            <RecordingIcon />
          ) : (
            <SparkMicLine />
          )
        }
        onClick={toggleRecording}
        disabled={isDisabled}
        style={{
          color: recording || loading ? "#1890ff" : undefined,
        }}
      />
    </Tooltip>
  );
});

WhisperSpeechButton.displayName = "WhisperSpeechButton";

export default WhisperSpeechButton;
