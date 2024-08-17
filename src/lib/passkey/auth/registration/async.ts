export const mapAsync = <T, R>(
  array: T[],
  callback: (item: T, index: number, array: T[]) => Promise<R>,
): Promise<R[]> => Promise.all(array.map(callback));
