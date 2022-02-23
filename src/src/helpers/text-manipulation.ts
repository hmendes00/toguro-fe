export const GetLettersForAvatar = (text: string) => {
  if (!text.length) {
    return text;
  }
  // we need at least 2 characters
  if (text.length < 2) {
    text += text; //adding one character
  }
  const splitted = text.split(/[\s\_]+/);

  return `${splitted[0][0]}${splitted[1] ? splitted[1][0] : splitted[0][1]}`.toUpperCase();
};
