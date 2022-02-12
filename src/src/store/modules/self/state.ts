export interface SelfState {
  isLoggedIn: boolean;
  username: string;
  email: string;
}

const state: SelfState = {
  isLoggedIn: true,
  username: 'TfeUser1',
  email: 'tfeuser1@gmail.com'
};

export default state;
