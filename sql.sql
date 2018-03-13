-- Working example
select
  vendors_1.name as name,
  count() as count
from
  arping
join
  (select
    mac_vendor.mac as mac,
    vendors.l_name as name
    from
      mac_vendor
      join
        vendors on
        mac_vendor.vendor = vendors.id
  ) as vendors_1 on
  SUBSTR(arping.mac,1,6) = vendors_1.mac
group by name
order by name;


select
  vendors_1.name as name,
  count() as count
from
  arping
join
  (select
    mac_vendor.mac as mac,
    vendors.l_name as name
    from
      mac_vendor
      join
        vendors on
        mac_vendor.vendor = vendors.id
  ) as vendors_1 on
  arping.mac like vendors_1.mac || "%"
group by name
order by count;
