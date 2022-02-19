export interface SelfState {
  isLoggedIn: boolean;
  username: string;
  email: string;
  appLogoutFunction?: Function;
}

const state: SelfState = {
  isLoggedIn: false,
  username: 'TfeUser1',
  email: 'tfeuser1@gmail.com',
  appLogoutFunction: () => {}
};

export default state;
