export interface SelfState {
  isLoggedIn: boolean;
  appLogoutFunction?: Function;
}

const state: SelfState = {
  isLoggedIn: false,
  appLogoutFunction: () => {}
};

export default state;
