//! Сужение имени до ключа — три исхода, не строка. `narrow: fn(&str) -> &str` возвращал одну строку
//! на три исхода, а `psl::domain_str(host).unwrap_or(host)` сливал их молча: замер поля 28.08 — у
//! 78 имён (23,9 %) и 698 флоу (20,3 %) ключ равен ПОЛНОМУ имени, хотя сужать было что. Фолбэк не
//! сработал ни разу — `googleapis.com` в ЧАСТНОЙ секции списка суффиксов, вырождение прячется в
//! успешном ответе. Закон здесь (крейт без `alloc`): ключ считается в темпе рукопожатия, тип несёт
//! только заимствованные срезы входа.

/// Что таблицы сказали об имени. Наблюдение, снятое вызывающим. Три слова: справочник может не
/// знать сервиса, а список суффиксов — объявить зону частной, и это разные факты.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said<'a> {
    /// Справочник семейств назвал сервис — курируемый ответ о хозяине.
    Service(&'a str),
    /// Справочник молчит; зона в ICANN-секции, регистрируемый домен.
    Registrable(&'a str),
    /// Справочник молчит; граница в ЧАСТНОЙ секции — арендатор под чужой зоной
    /// (`user.github.io`), не регистрация.
    Tenant(&'a str),
}

/// Ключ и что с именем случилось. Алгебраический: вырождение — законный исход (справочник покрывает
/// 82,6 % имён). Ветки «ключа нет» не существует.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Narrowed<'a> {
    /// Опознано справочником: знание делится со всеми узлами сервиса.
    Family(&'a str),
    /// Сужено списком до регистрируемого домена: за ключом один регистрант.
    Registrable(&'a str),
    /// Арендатор под чужой зоной: за соседей список не отвечает (`github.io` — чужие,
    /// `googleapis.com` — свои, различить не умеет).
    TenantZone(&'a str),
}

/// Как далеко переносится знание под ключом. Ради этого различения тип и заводится: ключ у
/// `Registrable` и `TenantZone` может совпасть по строке, а хозяин за ним разный.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carry {
    /// На все узлы сервиса — хозяина назвал справочник.
    Service,
    /// На поддомены регистрируемого домена: за ним один регистрант.
    Domain,
    /// Не дальше арендатора. Формой похоже на `Domain`, посылка другая: список утверждает лишь
    /// границу регистрации. Цена: когда арендатор совпал с FQDN (698 флоу поля), знание не сходится
    /// никогда (#146); снимает только курируемое опровержение справочником.
    Tenant,
}

/// Тотальная проекция: имя плюс слово таблиц — ключ со значением. «Ключа нет» невыразимо.
pub fn narrow(said: Said<'_>) -> Narrowed<'_> {
    match said {
        Said::Service(family) => Narrowed::Family(family),
        Said::Registrable(domain) => Narrowed::Registrable(domain),
        Said::Tenant(tenant) => Narrowed::TenantZone(tenant),
    }
}

impl<'a> Narrowed<'a> {
    /// Ключ, под которым копится знание.
    pub fn key(self) -> &'a str {
        match self {
            Narrowed::Family(key) => key,
            Narrowed::Registrable(key) => key,
            Narrowed::TenantZone(key) => key,
        }
    }

    /// Куда знание переносится. Единственное место, где три исхода расходятся последствиями, а не
    /// названием.
    pub fn carry(self) -> Carry {
        match self {
            Narrowed::Family(_) => Carry::Service,
            Narrowed::Registrable(_) => Carry::Domain,
            Narrowed::TenantZone(_) => Carry::Tenant,
        }
    }

    /// Не сузилось ничего: ключ равен входу. Мера, а не вариант — законна у имени из двух меток
    /// (`example.com` накрывает поддомены) и разорительна под частной зоной, оттого спрашивается
    /// вместе с [`Carry`].
    pub fn is_whole(self, host: &str) -> bool {
        self.key() == host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Одинаковый ключ при разном хозяине — ради этого случая тип и заведён.
    #[test]
    fn the_same_key_can_stand_for_different_owners() {
        let registrable = narrow(Said::Registrable("a.io"));
        let tenant = narrow(Said::Tenant("a.io"));
        assert_eq!(registrable.key(), tenant.key());
        assert_ne!(registrable.carry(), tenant.carry());
    }

    /// Арендатор, совпавший с полным именем, — та самая замеренная беда (698 флоу поля).
    #[test]
    fn a_tenant_equal_to_the_whole_name_is_the_measured_harm() {
        let narrowed = narrow(Said::Tenant("android.googleapis.com"));
        assert_eq!(narrowed.carry(), Carry::Tenant);
        assert!(narrowed.is_whole("android.googleapis.com"));
    }

    /// Имя из двух меток под обычной зоной — не беда, хотя ключ тоже равен входу.
    #[test]
    fn a_whole_key_under_an_icann_zone_is_not_harm() {
        let narrowed = narrow(Said::Registrable("example.com"));
        assert!(narrowed.is_whole("example.com"));
        assert_eq!(narrowed.carry(), Carry::Domain);
    }

    /// Справочник опровергает частный суффикс: список сказал «арендаторы», куратор знает хозяина.
    #[test]
    fn the_directory_overrules_a_private_suffix() {
        let narrowed = narrow(Said::Service("google"));
        assert_eq!(narrowed.key(), "google");
        assert_eq!(narrowed.carry(), Carry::Service);
        assert!(!narrowed.is_whole("android.googleapis.com"));
    }
}
