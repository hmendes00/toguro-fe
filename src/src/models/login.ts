export interface AppLoginInterface {
  isLoggedIn: boolean;
  accessToken: string;
  logoutFunction?: Function;
}
