import TfeIconButton from '@components/icon-button/icon-button.vue';
import TfeDrawerMenu from '@containers/drawer-menu/drawer-menu.vue';
import { defineComponent } from 'vue';
import { mapGetters } from 'vuex';

export default defineComponent({
  components: {
    TfeIconButton,
    TfeDrawerMenu
  },
  computed: {
    ...mapGetters('self', ['isLoggedIn'])
  }
});
