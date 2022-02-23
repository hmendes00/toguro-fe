export interface UserSearched {
  user_id: string;
  display_name?: string;
  avatar_url?: string;
}

export interface UserDirectoryResponse {
  results: UserSearched[];
  limited: boolean;
}
