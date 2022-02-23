import { UserDirectoryResponse } from '@/models/matrix';
import { ConfigService } from '@/services/config.service';
import { useFetch } from '@vueuse/core';
import {
  Callback,
  createClient,
  Filter,
  IUploadOpts,
  MatrixClient,
  MatrixEvent,
  Room,
  User,
  IFilterDefinition
} from 'matrix-js-sdk';
import { IImageInfo } from 'matrix-js-sdk/lib/@types/partials';

let mxClient: MatrixClient;
let mxMyUser: User;
export const getDeviceId = () => localStorage.getItem(ConfigService.mxDeviceKey) || '';
export const getUserId = () => localStorage.getItem(ConfigService.mxUserId) || '';
export const getFilterId = () => localStorage.getItem(ConfigService.mxFilterKey) || '';
export const setFilterId = (value: string) => localStorage.setItem(ConfigService.mxFilterKey, value);
export const getClient = () => mxClient;

export const DoFirstSync = () => {
  return new Promise((resolve, reject) => {
    mxClient.once('sync', async (state) => {
      switch (state) {
        case 'PREPARED':
          mxClient.removeListener('sync', DoFirstSync);
          resolve(true);
          break;
        case 'ERROR':
          mxClient.removeListener('sync', DoFirstSync);
          reject('Error when syncing');
          break;
      }
    });
  });
};

const createFilter = (roomIds: string[]) => {
  const roomFilter = {
    not_rooms: roomIds,
    ephemeral: {
      not_types: ['m.receipt', 'm.typing', 'm.presence']
    },
    state: {
      lazy_load_members: true,
      limit: 0
    },
    timeline: {
      limit: 0
    }
  };

  const filterDef: IFilterDefinition = {
    room: roomFilter,
    account_data: { not_types: ['m.tag'] }
  };

  return mxClient.createFilter(filterDef);
};

export const SetClient = async (accessToken: string) => {
  mxClient = createClient({
    baseUrl: ConfigService.MatrixUrl,
    userId: getUserId(),
    deviceId: getDeviceId(),
    accessToken
  });

  let _filter: Filter;
  const filterId = getFilterId();
  if (filterId) {
    _filter = await mxClient.getFilter(getUserId(), filterId, true);
  } else {
    _filter = await createFilter([]);
    setFilterId(_filter.filterId || '');
  }
  await mxClient.startClient({
    initialSyncLimit: 0,
    disablePresence: true,
    lazyLoadMembers: true,
    pollTimeout: 40000,
    filter: _filter
  });
  // wait for first sync so we get profile, etc ready
  await DoFirstSync();
  mxMyUser = mxClient.getUser(getUserId());
};

export const GetMxImage = (mxUrl?: string, width = 50, height = 50) => {
  if (!mxUrl) {
    return;
  }

  return mxClient.mxcUrlToHttp(mxUrl, width, height, 'scale') || undefined;
};

export const GetSenderAvatar = (item: MatrixEvent) => {
  if (!item) {
    return ConfigService.defaultAvatar;
  }
  return item.sender.getAvatarUrl(ConfigService.MatrixUrl, 50, 50, 'scale', true, false) || ConfigService.defaultAvatar;
};

export const GetMyUser = () => {
  return mxMyUser;
};

export const GetMyAvatarUrl = () => {
  return GetMxImage(GetMyUser().avatarUrl) || '';
};

export const GetUserById = (userId: string): User => {
  return mxClient.getUser(userId);
};

export const GetUserAvatarUrl = (userId: string) => {
  return GetMxImage(GetUserById(userId).avatarUrl) || '';
};

export const GetDisplayName = () => {
  return GetMyUser().rawDisplayName;
};
export const GetUsername = () => {
  return mxClient.getUserIdLocalpart();
};

export const GetRoomAvatar = (room: Room) => {
  if (!room) {
    return ConfigService.defaultAvatar;
  }
  let roomAvatar = room.getAvatarUrl(ConfigService.MatrixUrl, 100, 100, 'scale', true);
  if (!roomAvatar && room.getJoinedMemberCount() === 2) {
    roomAvatar = room.getAvatarFallbackMember().getAvatarUrl(ConfigService.MatrixUrl, 100, 100, 'scale', true, false);
  }
  return roomAvatar || ConfigService.defaultAvatar;
};

export const GetEventTime = (item: MatrixEvent) => {
  const _date = item.getDate()!;
  return `${_date.getHours()}:${_date.getMinutes() > 9 ? _date.getMinutes() : '0' + _date.getMinutes()}`;
};

export const SendMessage = (roomId: string, body: string, callBack?: Callback) => {
  const txnId = mxClient.makeTxnId();
  mxClient.sendTextMessage(roomId, body, txnId, callBack);
};

export const UploadContent = (file: File, opts?: IUploadOpts) => {
  return mxClient.uploadContent(file, opts);
};

export const SendImage = (roomId: string, mxUrl: string, info?: IImageInfo, text?: string, callback?: Callback) => {
  mxClient.sendImageMessage(roomId, mxUrl, info, text, callback);
};

export const SearchUsers = async (term: string): Promise<UserDirectoryResponse | undefined> => {
  if (!term.length) {
    return;
  }
  // the limit here seems to be based on indexes. that means the when limit = 3, it will bring 4. (0,1,2,3);
  return await mxClient.searchUserDirectory({ term, limit: 3 });
};
