export type CreatePayload = {
  userId: number;
  credentialId: string;
  publicKey: string;
  counter: number;
  transports: string;
};

export type UpdatePayload = {
  userId?: number;
  credentialId?: string;
  publicKey?: string;
  counter?: number;
  transports?: string;
};
