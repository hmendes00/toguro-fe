export enum DrawerState {
  OPENED,
  OPENING,
  CLOSED
}

export interface AppState {
  appLoaded: boolean;
  drawerState: DrawerState;
  customApps: Record<string, CustomApp>;
}

export type CustomApp = {
  appName: string;
  appId: string;
  appUrl: string;
  developerEmail: string;
  appVersion: string;
  target: string;
  appType: string;
  label: string;
  hasSupport: boolean;
};

const state: AppState = {
  appLoaded: false,
  drawerState: DrawerState.CLOSED,
  customApps: {}
};

export default state;
