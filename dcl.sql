/* =====================================================================
   BogoTickets
   Autor: Dilan Alejandro Sanchez Escobar
   =====================================================================
   Usuarios:
     usuario_app       -> la aplicación web (módulo de cliente)
     usuario_reportes  -> el Analista de ventas, solo lectura (RNF-04),
                          hereda sus permisos de rol_lectura
     admin_escenarios  -> el Administrador de Escenarios y Eventos
   ===================================================================== */

SET client_min_messages = warning;

-- 0. Limpieza (quita permisos y borra los roles si ya existen)
DO $$
DECLARE r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['usuario_app', 'usuario_reportes',
                             'admin_escenarios', 'rol_lectura'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('DROP OWNED BY %I', r);
            EXECUTE format('DROP ROLE %I', r);
        END IF;
    END LOOP;
END $$;

-- 1. Roles y usuarios (CREATE USER = CREATE ROLE + LOGIN)
CREATE ROLE rol_lectura NOLOGIN;
CREATE USER usuario_app      PASSWORD 'Cambiar_App_2026';
CREATE USER usuario_reportes PASSWORD 'Cambiar_Rep_2026';
CREATE USER admin_escenarios PASSWORD 'Cambiar_Adm_2026';
GRANT rol_lectura TO usuario_reportes;

-- 2. REVOKE: nadie tiene permisos "por defecto" (PUBLIC = todos los usuarios)
REVOKE ALL    ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;   -- nadie crea tablas en public
DO $$
BEGIN   -- conectarse a ESTA base (current_database() evita escribir su nombre)
    EXECUTE format('GRANT CONNECT ON DATABASE %I '
                   'TO usuario_app, usuario_reportes, admin_escenarios',
                   current_database());
END $$;
GRANT USAGE ON SCHEMA public TO usuario_app, rol_lectura, admin_escenarios;

-- 3. usuario_app (operación): solo lo que hace el módulo de cliente
--    Catálogo de eventos y disponibilidad (RF-06, RF-07): solo lectura
GRANT SELECT         ON escenario, localidad, evento, precio_localidad TO usuario_app;
--    Registro de clientes (RF-05) y compra de boletas (RF-08, RF-09)
GRANT SELECT, INSERT ON cliente, boleta TO usuario_app;
--    El cliente solo puede actualizar sus datos de contacto
GRANT UPDATE (correo, telefono) ON cliente TO usuario_app;
--    Secuencias: NO se dan. Nuestras PK son IDENTITY (no SERIAL): PostgreSQL usa
--    la secuencia por dentro sin pedir USAGE. Lo probamos: sin ese permiso el
--    INSERT funciona, así que darlo sería un privilegio de más.
--    Vistas que usa la app: historial de compras y cupos disponibles
GRANT SELECT ON v_boletas_detalle, v_ocupacion_localidad TO usuario_app;

-- 4. rol_lectura -> usuario_reportes (Analista): solo vistas, ninguna tabla base
GRANT SELECT ON v_ocupacion_localidad, v_boletas_detalle, v_clientes_publico TO rol_lectura;

-- 5. admin_escenarios: catálogo de escenarios, localidades, eventos y precios
GRANT SELECT, INSERT ON escenario, localidad, evento, precio_localidad TO admin_escenarios;
GRANT UPDATE (nombre, direccion, capacidad_maxima) ON escenario        TO admin_escenarios;
GRANT UPDATE (nombre, aforo_maximo)                ON localidad        TO admin_escenarios;
GRANT UPDATE (nombre, fecha, hora_inicio)          ON evento           TO admin_escenarios;
GRANT UPDATE (precio)                              ON precio_localidad TO admin_escenarios;
GRANT SELECT, INSERT ON historial_precios TO admin_escenarios;   -- auditoría (RNF-06)
GRANT SELECT ON boleta TO admin_escenarios;
GRANT UPDATE (estado) ON boleta TO admin_escenarios;   -- cancelar, nunca borrar (RNF-07)
GRANT SELECT ON v_ocupacion_localidad, v_boletas_vigentes TO admin_escenarios;

-- 6. REVOKE explícitos (documentan lo que NUNCA se debe dar; aseguran el estado final)
-- La auditoría no es de la app ni del analista:
REVOKE ALL ON historial_precios FROM usuario_app, rol_lectura;
-- Los datos personales de los clientes quedan protegidos:
REVOKE ALL ON cliente FROM rol_lectura, admin_escenarios;
-- Nadie borra (RNF-07, RN-14):
REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public
       FROM usuario_app, rol_lectura, admin_escenarios;

-- 7. Resultado: los 4 roles creados
SELECT r.rolname                                      AS usuario_o_rol,
       r.rolcanlogin                                  AS puede_iniciar_sesion,
       r.rolsuper                                     AS es_superusuario,
       COALESCE(string_agg(g.rolname, ', '), '—')     AS hereda_de
FROM   pg_roles r
LEFT   JOIN pg_auth_members m ON m.member = r.oid
LEFT   JOIN pg_roles g        ON g.oid    = m.roleid
WHERE  r.rolname IN ('usuario_app', 'usuario_reportes', 'admin_escenarios', 'rol_lectura')
GROUP  BY r.rolname, r.rolcanlogin, r.rolsuper
ORDER  BY r.rolcanlogin DESC, r.rolname;
