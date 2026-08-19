import { create } from "zustand";

export interface AuthorizationSnapshot {
  authEnabled: boolean;
  username: string | null;
  roles: string[];
  canMutate: boolean;
}

interface AuthorizationState extends AuthorizationSnapshot {
  setAuthorization: (authorization: AuthorizationSnapshot) => void;
  set: (authorization: AuthorizationSnapshot) => void;
  reset: () => void;
}

const initialAuthorization: AuthorizationSnapshot = {
  authEnabled: false,
  username: null,
  roles: [],
  canMutate: false,
};

export const useAuthorizationStore = create<AuthorizationState>((set) => ({
  ...initialAuthorization,
  setAuthorization: (authorization) => set(authorization),
  set: (authorization) => set(authorization),
  reset: () => set(initialAuthorization),
}));
