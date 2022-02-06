export interface SelfState {
  isLoggedIn: boolean;
  username: string;
  email: string;
}

const state: SelfState = {
  isLoggedIn: true,
  username: 'GsnUser1',
  email: 'gsnuser1@gmail.com'
};

export default state;
