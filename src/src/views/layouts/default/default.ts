import GsnIconButton from '@components/icon-button/icon-button.vue';
import GsnDrawerMenu from '@containers/drawer-menu/drawer-menu.vue';
import { defineComponent } from 'vue';
import { mapGetters } from 'vuex';

export default defineComponent({
  components: {
    GsnIconButton,
    GsnDrawerMenu
  },
  computed: {
    ...mapGetters('self', ['isLoggedIn'])
  }
});
