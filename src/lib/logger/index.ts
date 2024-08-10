export const log =
  <T, Q>(callback: (data: T) => Q) =>
  (error: Error) => {
    console.log(error);

    return (data: T) => callback(data);
  };
