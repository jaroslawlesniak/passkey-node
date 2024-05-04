export const uint8ArrayToBase64 = (uint8Array: Uint8Array): string =>
  Buffer.from(uint8Array).toString('base64');

export const base64ToUint8Array = (base64: string): Uint8Array =>
  new Uint8Array(Buffer.from(base64, 'base64'));

export const numberToUint8 = (num: number) => {
  let arr = new Uint8Array(8);

  for (let i = 0; i < 8; i++) {
    arr[i] = num % 256;
    num = Math.floor(num / 256);
  }

  return arr;
}
